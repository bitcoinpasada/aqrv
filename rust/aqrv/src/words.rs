//! The words form (`https://github.com/bitcoinpasada/aqrv`, `AQRV.md` §3.2): an
//! envelope of 37, 53 or 62 bytes written as words of SLIP-0039's list, ten
//! bits a word, then six Reed–Solomon check words over GF(1024), and read
//! back from a list of positions, correcting what the check allows.
//!
//! The words are the envelope's bytes in another form, and an envelope is
//! not secret (a QR code shows it), so they are held as plain strings and
//! bytes. [`read_text`] (in `paste.rs`) reads words pasted or typed as free text.

mod gf;
mod paste;

use std::sync::LazyLock;

use crate::{Size, Step, recognise};

pub use paste::{NotTextWords, read_text};

/// SLIP-0039's word list, `wordlist.txt` of SLIP-0039 and of Trezor's
/// `python-shamir-mnemonic`, one word a line (§3.2).
pub const WORD_LIST: &str = include_str!("wordlist.txt");

/// The 1024 words, a word's value its line counted from 0.
static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| WORD_LIST.lines().collect());

/// §3.2's customization string, each byte one symbol.
const CS: &[u8] = b"argon-qr-vault-1 words";

/// The number of check words.
const CHECKS: usize = 6;

/// The correction rule's bound: `2e + f` at most this (§3.2 Reading step 4).
const RULE: usize = 4;

/// The size a number of words stands for, if any (§3.2 Reading step 2).
fn size_of_count(n: usize) -> Option<Size> {
    match n {
        36 => Some(Size::Words),
        48 => Some(Size::Small),
        56 => Some(Size::Large),
        _ => None,
    }
}

/// The data words of an envelope of `bytes` bytes: its bits after the
/// 5-bit marker, ten a word, rounded up.
const fn data_words(bytes: usize) -> usize {
    (bytes * 8 - 5).div_ceil(10)
}

/// Why [`to_words`] wrote nothing (§3.2 Writing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoWords {
    /// A 32-byte envelope: its 11-byte salt has no words form. Sealing the
    /// item again at 37 bytes makes one that has.
    TinySize,
    /// Not 37, 53 or 62 bytes beginning 0xF8 to 0xFC.
    NotAnEnvelope,
}

/// Why [`from_words`] gave no envelope (§3.2 Reading). Neither asks for a
/// passphrase, and each is said in words distinct from "does not open".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotWords {
    /// The words do not check, and no correction within `2e + f <= 4`
    /// makes them; or a correction gave bits no writer makes (step 5).
    DoNotCheck,
    /// Not AQRV words, for the reason given.
    NotAqrv(NotAqrvWords),
}

/// Why a list is not AQRV words (§3.2 Reading steps 2 and 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotAqrvWords {
    /// This many positions, where a size needs 36, 48 or 56.
    Count(usize),
    /// The words check, and the last data word's unused bits are not all 0.
    UnusedBits,
    /// The words check, and the step is one §4 does not define (5 to 7).
    Step,
}

/// A position that a reading filled or changed (§3.2 Reading step 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Correction {
    /// The position, counted from 1.
    pub position: usize,
    /// What the position held, as given.
    pub input: String,
    /// The word put there.
    pub word: &'static str,
}

/// Words read to an envelope (§3.2 Reading).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadWords {
    /// The envelope, 37, 53 or 62 bytes: what [`crate::open`] takes.
    pub envelope: Vec<u8>,
    /// Every word, corrected, data words then check words.
    pub words: Vec<&'static str>,
    /// The positions that were unreadable and were filled, counted from 1.
    pub unreadable: Vec<usize>,
    /// The positions whose word was wrong and was changed, counted from 1.
    pub wrong: Vec<usize>,
    /// Every position filled or changed, by position, with what it held and
    /// the word put there: shown before a passphrase is asked for.
    pub corrected: Vec<Correction>,
}

/// The check words of a list of data words (§3.2 Check words).
fn check_words(data: &[u16]) -> [u16; CHECKS] {
    let symbols = CS.iter().map(|&b| u16::from(b)).chain(data.iter().copied());
    let mut rem = gf::polymod(&gf::GENERATOR, symbols.chain([0; CHECKS]));
    rem[CHECKS - 1] ^= 1;
    rem
}

/// Whether a whole list of values, data then check, is valid (§3.2).
fn valid(values: &[u16]) -> bool {
    let symbols = CS
        .iter()
        .map(|&b| u16::from(b))
        .chain(values.iter().copied());
    gf::polymod(&gf::GENERATOR, symbols) == [0, 0, 0, 0, 0, 1]
}

/// Whether every position names a word and the words are valid as they
/// are, with nothing to correct.
fn checks(positions: &[&str]) -> bool {
    let values: Option<Vec<u16>> = positions.iter().map(|p| name(p)).collect();
    values.is_some_and(|v| valid(&v))
}

/// §3.2 Writing: an envelope of 37, 53 or 62 bytes as its words, data words
/// then check words. A 32-byte envelope is refused.
pub fn to_words(envelope: &[u8]) -> Result<Vec<&'static str>, NoWords> {
    let header = recognise(envelope).ok_or(NoWords::NotAnEnvelope)?;
    if header.size == Size::Tiny {
        return Err(NoWords::TinySize);
    }
    let data = data_values(envelope);
    let check = check_words(&data);
    Ok(data
        .iter()
        .chain(check.iter())
        .map(|&v| WORDS[usize::from(v)])
        .collect())
}

/// The data words' values: the envelope's bits after the marker, ten a
/// word, the last one's unused low bits 0.
fn data_values(envelope: &[u8]) -> Vec<u16> {
    let bits = envelope.len() * 8;
    let bit = |i: usize| (envelope[i / 8] >> (7 - i % 8)) & 1;
    (0..data_words(envelope.len()))
        .map(|w| {
            (0..10).fold(0u16, |v, k| {
                let i = 5 + w * 10 + k;
                (v << 1) | if i < bits { u16::from(bit(i)) } else { 0 }
            })
        })
        .collect()
}

/// §3.2 Reading step 1: the value of the word a position names, if it
/// names one. ASCII letters only, compared without regard to case; four
/// letters name a word, and more must all match it.
pub(crate) fn name(given: &str) -> Option<u16> {
    let b = given.as_bytes();
    if b.len() < 4 || b.len() > 8 || !b.iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let lower: Vec<u8> = b.iter().map(u8::to_ascii_lowercase).collect();
    let i = WORDS
        .binary_search_by(|w| w.as_bytes()[..4].cmp(&lower[..4]))
        .ok()?;
    let word = WORDS[i].as_bytes();
    (lower.len() <= word.len() && word[..lower.len()] == lower[..]).then_some(i as u16)
}

/// §3.2 Reading: a list of positions, each a word as given (by its first
/// four letters or more, any case) or anything else for a position that
/// cannot be read, such as `?`, to the envelope.
pub fn from_words<S: AsRef<str>>(positions: &[S]) -> Result<ReadWords, NotWords> {
    read_within(positions, RULE)
}

/// [`from_words`] with the correction's bound given: `2e + f <= budget`.
pub(crate) fn read_within<S: AsRef<str>>(
    positions: &[S],
    budget: usize,
) -> Result<ReadWords, NotWords> {
    let n = positions.len();
    let size = size_of_count(n).ok_or(NotWords::NotAqrv(NotAqrvWords::Count(n)))?;
    let named: Vec<Option<u16>> = positions.iter().map(|p| name(p.as_ref())).collect();
    let erased: Vec<usize> = (0..n).filter(|&i| named[i].is_none()).collect();
    let mut values: Vec<u16> = named.iter().map(|v| v.unwrap_or(0)).collect();

    let mut wrong = Vec::new();
    if !erased.is_empty() || !valid(&values) {
        let fixes = decode(&values, &erased, budget).ok_or(NotWords::DoNotCheck)?;
        for (i, magnitude) in fixes {
            if !erased.contains(&i) {
                wrong.push(i);
            }
            values[i] ^= magnitude;
        }
        wrong.sort_unstable();
    }
    let corrected_any = !erased.is_empty() || !wrong.is_empty();

    let data = &values[..data_words(size.bytes())];
    let envelope = match envelope_of(data, size) {
        Ok(e) => e,
        Err(_) if corrected_any => return Err(NotWords::DoNotCheck),
        Err(why) => return Err(NotWords::NotAqrv(why)),
    };
    let words: Vec<&'static str> = values.iter().map(|&v| WORDS[usize::from(v)]).collect();
    let mut changed: Vec<usize> = erased.iter().chain(wrong.iter()).copied().collect();
    changed.sort_unstable();
    let corrected = changed
        .into_iter()
        .map(|i| Correction {
            position: i + 1,
            input: positions[i].as_ref().to_string(),
            word: words[i],
        })
        .collect();
    Ok(ReadWords {
        envelope,
        words,
        unreadable: erased.iter().map(|i| i + 1).collect(),
        wrong: wrong.iter().map(|i| i + 1).collect(),
        corrected,
    })
}

/// §3.2 Reading step 5: the data words' bits, the marker put back in front,
/// as the envelope of `size`; refused for unused bits other than 0 or an
/// undefined step.
fn envelope_of(data: &[u16], size: Size) -> Result<Vec<u8>, NotAqrvWords> {
    let mut bits: Vec<u8> = vec![1; 5];
    for &v in data {
        bits.extend((0..10).rev().map(|k| ((v >> k) & 1) as u8));
    }
    let n = size.bytes();
    if bits[n * 8..].iter().any(|&b| b != 0) {
        return Err(NotAqrvWords::UnusedBits);
    }
    let envelope: Vec<u8> = bits[..n * 8]
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b))
        .collect();
    if Step::of_header(envelope[0]).is_none() {
        return Err(NotAqrvWords::Step);
    }
    Ok(envelope)
}

/// §3.2 Reading step 4: the fixes, as (index into `values`, value to xor
/// in), that make the words valid with the positions in `erased` filled
/// and at most `e` others changed, `2e + f <= budget`; the fewest changes
/// first. With the code's distance of 7 and `budget` at most 6, a fix
/// found is the only one within the bound.
///
/// Each guess of the wrong positions is solved, with the erased ones, as
/// unknown values at known places: the syndromes at `a^1` to `a^6` of the
/// whole sequence (the leading 1, `cs`, the words with the last one's low
/// bit flipped) give six equations, which a guess of at most six unknowns
/// must satisfy exactly. The leading 1 and `cs` are never unknowns.
fn decode(values: &[u16], erased: &[usize], budget: usize) -> Option<Vec<(usize, u16)>> {
    let f = erased.len();
    if f > budget || f > CHECKS {
        return None;
    }
    let mut sequence: Vec<u16> = Vec::with_capacity(1 + CS.len() + values.len());
    sequence.push(1);
    sequence.extend(CS.iter().map(|&b| u16::from(b)));
    sequence.extend_from_slice(values);
    *sequence.last_mut()? ^= 1;
    let len = sequence.len();
    let offset = 1 + CS.len();
    let power = |i: usize| (len - 1 - (offset + i)) as u32;
    let syndromes: [u16; CHECKS] =
        std::array::from_fn(|j| gf::eval(&sequence, gf::exp(j as u32 + 1)));

    let others: Vec<usize> = (0..values.len()).filter(|i| !erased.contains(i)).collect();
    let mut e = 0;
    while 2 * e + f <= budget && e + f <= CHECKS {
        let mut found = None;
        gf::each_combination(others.len(), e, &mut |pick| {
            let mut unknown: Vec<usize> = erased.to_vec();
            unknown.extend(pick.iter().map(|&k| others[k]));
            let places: Vec<u32> = unknown.iter().map(|&i| power(i)).collect();
            match gf::solve(&places, &syndromes) {
                Some(y) if y[f..].iter().all(|&m| m != 0) => {
                    found = Some(unknown.into_iter().zip(y).collect());
                    true
                }
                _ => false,
            }
        });
        if found.is_some() {
            return found;
        }
        e += 1;
    }
    None
}

#[cfg(test)]
mod tests;
