//! Words pasted or typed as free text: with or without spaces, across
//! lines, numbered, by their first four letters or in full, in any case.
//!
//! - Separators: every character that is not a letter, not a combining
//!   mark and not `?` separates words: whitespace of every kind, ASCII
//!   digits and punctuation, and every other non-letter such as the
//!   no-break space, the zero-width space, the byte order mark, bullets,
//!   dashes, curly quotes and full-width punctuation. Runs of them, and
//!   any at the start or end, are ignored.
//! - A hyphen followed by a line break, with only spaces or tabs between
//!   and around, joins the letters on either side (`aca-` then `demic` on
//!   the next line is `academic`).
//! - A run of one or more `?` is one position marked unreadable, with
//!   letters on either side or not. A run that holds anything but ASCII
//!   letters (a letter of another script, a combining mark) is one
//!   unreadable position: it is never turned into a word.
//! - Numbers only separate, unless every run is preceded by a number and
//!   those numbers are exactly 1 to the number of runs, each once: then the
//!   runs are put in the numbers' order, so that a grid copied column by
//!   column reads in its numbered order.
//! - A run of ASCII letters may hold several words run together, each
//!   given by four letters or more of a word of the list; it is cut into
//!   such pieces every way it can be, and a run that cannot be cut is one
//!   unreadable position. Other text (a heading pasted with the words) is
//!   read the same way, so the count or the check reports it.
//!
//! A run may be cut in more than one way. Every reading of the whole text
//! whose count is 36, 48 or 56 is read by [`super::from_words`]: those
//! that check as they are first, then with correction; the one that checks
//! is the result. More than one that checks to different envelopes, or too
//! many readings to try, is refused rather than guessed.

use super::{NotAqrvWords, NotWords, ReadWords, checks, from_words, name, size_of_count};

/// The longest text read, in bytes: far more than 56 numbered words.
const MAX_TEXT: usize = 16 * 1024;

/// The most readings of one run, or of the whole text, that are tried.
const MAX_READINGS: usize = 1024;

/// The most words a reading can have.
const MAX_WORDS: usize = 56;

/// Why [`read_text`] gave no envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotTextWords {
    /// What [`super::from_words`] says of the one reading the text has, or
    /// of every reading when none checks.
    Words(NotWords),
    /// Words run together can be read in more than one way, and more than
    /// one way checks, to different envelopes: separate the words.
    Ambiguous,
    /// More ways to cut the words run together than are tried, or a text
    /// longer than any sheet of words: separate the words.
    TooMany,
}

/// A piece of the text: a run of ASCII letters, or one position that
/// cannot be read, as given.
enum Run<'a> {
    Letters(&'a str),
    Unreadable(&'a str),
}

/// Whether `c` is a combining mark of the blocks that hold Latin's
/// accents, which joins the run it is in and makes it unreadable.
fn combining(c: char) -> bool {
    matches!(c,
        '\u{0300}'..='\u{036F}'
        | '\u{1AB0}'..='\u{1AFF}'
        | '\u{1DC0}'..='\u{1DFF}'
        | '\u{20D0}'..='\u{20FF}'
        | '\u{FE20}'..='\u{FE2F}')
}

/// Whether `c` belongs to a run rather than separating runs.
fn in_run(c: char) -> bool {
    c.is_alphabetic() || c == '?' || combining(c)
}

/// The text with every hyphen that ends a line removed, with the line
/// break and the spaces around it, where letters are on both sides.
fn join_wraps(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '-' && i > 0 && chars[i - 1].is_alphabetic() {
            let mut j = i + 1;
            while j < chars.len() && matches!(chars[j], ' ' | '\t') {
                j += 1;
            }
            let mut broke = false;
            if j < chars.len() && chars[j] == '\r' {
                j += 1;
            }
            if j < chars.len() && chars[j] == '\n' {
                j += 1;
                broke = true;
            }
            while broke && j < chars.len() && matches!(chars[j], ' ' | '\t') {
                j += 1;
            }
            if broke && j < chars.len() && chars[j].is_alphabetic() {
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// The text's runs in order, each with the number written in the
/// separators just before it, if any.
fn runs(text: &str) -> Vec<(Option<u64>, Run<'_>)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut number: Option<u64> = None;
    let mut digits: Option<u64> = None;
    for (i, c) in text.char_indices().chain([(text.len(), ' ')]) {
        // A run of question marks is a run of its own, even against letters.
        let marks = start.is_some_and(|s| text[s..].starts_with('?'));
        if i < text.len() && in_run(c) && (start.is_none() || marks == (c == '?')) {
            if start.is_none() {
                start = Some(i);
                number = digits.take().or(number.take());
            }
            continue;
        }
        if let Some(s) = start.take() {
            out.push((number.take(), run_of(&text[s..i])));
        }
        if i < text.len() && in_run(c) {
            start = Some(i);
            continue;
        }
        if let Some(d) = c.to_digit(10).filter(|_| c.is_ascii_digit()) {
            let so_far = digits.unwrap_or(0);
            digits = Some(so_far.saturating_mul(10).saturating_add(u64::from(d)));
        } else if digits.is_some() {
            number = digits.take();
        }
    }
    order_by_numbers(out)
}

/// The runs in their numbers' order when every run has one and they are
/// exactly 1 to the number of runs; otherwise as they are.
fn order_by_numbers(runs: Vec<(Option<u64>, Run<'_>)>) -> Vec<(Option<u64>, Run<'_>)> {
    let n = runs.len() as u64;
    let mut seen = vec![false; runs.len()];
    let numbered = runs.iter().all(|(k, _)| match k {
        Some(k) if (1..=n).contains(k) && !seen[(*k - 1) as usize] => {
            seen[(*k - 1) as usize] = true;
            true
        }
        _ => false,
    });
    if !numbered || runs.is_empty() {
        return runs;
    }
    let mut runs = runs;
    runs.sort_by_key(|(k, _)| *k);
    runs
}

/// One run between separators: ASCII letters a run to cut; anything else,
/// question marks alone among them, one unreadable position.
fn run_of(s: &str) -> Run<'_> {
    if s.bytes().all(|b| b.is_ascii_alphabetic()) {
        Run::Letters(s)
    } else {
        Run::Unreadable(s)
    }
}

/// Every way to cut a run of letters into pieces that each name a word,
/// longest pieces first; None if more than [`MAX_READINGS`].
fn cuts(run: &str) -> Option<Vec<Vec<&str>>> {
    let n = run.len();
    // ways[i]: how many ways run[i..] can be cut, saturating.
    let mut ways = vec![0usize; n + 1];
    ways[n] = 1;
    for i in (0..n).rev() {
        ways[i] = (4..=8)
            .filter(|&k| i + k <= n && name(&run[i..i + k]).is_some())
            .fold(0usize, |w, k| w.saturating_add(ways[i + k]));
    }
    if ways[0] > MAX_READINGS {
        return None;
    }
    let mut out = Vec::new();
    let mut path = Vec::new();
    walk(run, 0, &ways, &mut path, &mut out);
    Some(out)
}

fn walk<'a>(
    run: &'a str,
    i: usize,
    ways: &[usize],
    path: &mut Vec<&'a str>,
    out: &mut Vec<Vec<&'a str>>,
) {
    if i == run.len() {
        out.push(path.clone());
        return;
    }
    for k in (4..=8).rev() {
        if i + k <= run.len() && ways[i + k] > 0 && name(&run[i..i + k]).is_some() {
            path.push(&run[i..i + k]);
            walk(run, i + k, ways, path, out);
            path.pop();
        }
    }
}

/// Words pasted or typed as free text, read to an envelope (§3.2 Reading,
/// with the text cut into positions as this module says). The result's
/// positions count the words as read from the text.
pub fn read_text(text: &str) -> Result<ReadWords, NotTextWords> {
    if text.len() > MAX_TEXT {
        return Err(NotTextWords::TooMany);
    }
    let text = join_wraps(text);
    // Each run's choices: a run of letters that cannot be cut is one
    // unreadable position, as given.
    let mut choices: Vec<Vec<Vec<&str>>> = Vec::new();
    for (_, run) in runs(&text) {
        choices.push(match run {
            Run::Unreadable(s) => vec![vec![s]],
            Run::Letters(s) => {
                let c = cuts(s).ok_or(NotTextWords::TooMany)?;
                if c.is_empty() { vec![vec![s]] } else { c }
            }
        });
    }
    // The reading taking each run's longest pieces: what a count is said of
    // when no reading has a count a size has.
    let longest: Vec<&str> = choices.iter().flat_map(|c| c[0].iter().copied()).collect();
    let readings = readings(&choices)?;
    pick(&readings, &longest)
}

/// Every reading of the whole text with at most [`MAX_WORDS`] positions;
/// too many is refused.
fn readings<'a>(choices: &[Vec<Vec<&'a str>>]) -> Result<Vec<Vec<&'a str>>, NotTextWords> {
    // fewest[r]: the fewest positions runs r.. can make.
    let mut fewest = vec![0usize; choices.len() + 1];
    for r in (0..choices.len()).rev() {
        let least = choices[r].iter().map(Vec::len).min().unwrap_or(0);
        fewest[r] = fewest[r + 1] + least;
    }
    let mut out = Vec::new();
    let mut path = Vec::new();
    let mut over = false;
    gather(choices, 0, &fewest, &mut path, &mut out, &mut over);
    if over {
        return Err(NotTextWords::TooMany);
    }
    Ok(out)
}

fn gather<'a>(
    choices: &[Vec<Vec<&'a str>>],
    r: usize,
    fewest: &[usize],
    path: &mut Vec<&'a str>,
    out: &mut Vec<Vec<&'a str>>,
    over: &mut bool,
) {
    if *over {
        return;
    }
    if r == choices.len() {
        if out.len() == MAX_READINGS {
            *over = true;
        } else {
            out.push(path.clone());
        }
        return;
    }
    for cut in &choices[r] {
        if path.len() + cut.len() + fewest[r + 1] > MAX_WORDS {
            continue;
        }
        let keep = path.len();
        path.extend_from_slice(cut);
        gather(choices, r + 1, fewest, path, out, over);
        path.truncate(keep);
    }
}

/// The reading that checks. With one reading, what it gives. With several,
/// those whose count a size has are tried, those that check as they are
/// first, then all of them with correction; the result is the one that
/// checks, the fewest corrections first when several give one envelope.
fn pick(readings: &[Vec<&str>], longest: &[&str]) -> Result<ReadWords, NotTextWords> {
    if readings.len() <= 1 {
        let only = readings.first().map_or(longest, Vec::as_slice);
        return from_words(only).map_err(NotTextWords::Words);
    }
    let counted: Vec<&Vec<&str>> = readings
        .iter()
        .filter(|r| size_of_count(r.len()).is_some())
        .collect();
    if counted.is_empty() {
        let n = readings[0].len();
        return Err(NotTextWords::Words(NotWords::NotAqrv(NotAqrvWords::Count(
            n,
        ))));
    }
    let exact: Vec<&Vec<&str>> = counted.iter().copied().filter(|r| checks(r)).collect();
    let tried = if exact.is_empty() { counted } else { exact };
    let mut read: Vec<ReadWords> = Vec::new();
    let mut not_aqrv = None;
    for reading in tried {
        match from_words(reading.as_slice()) {
            Ok(r) => read.push(r),
            Err(NotWords::NotAqrv(why)) => not_aqrv = Some(why),
            Err(NotWords::DoNotCheck) => {}
        }
    }
    read.sort_by_key(|r| r.corrected.len());
    let one_envelope = read.windows(2).all(|w| w[0].envelope == w[1].envelope);
    match (read.is_empty(), not_aqrv) {
        (false, None) if one_envelope => Ok(read.swap_remove(0)),
        (false, _) => Err(NotTextWords::Ambiguous),
        (true, Some(why)) => Err(NotTextWords::Words(NotWords::NotAqrv(why))),
        (true, None) => Err(NotTextWords::Words(NotWords::DoNotCheck)),
    }
}
