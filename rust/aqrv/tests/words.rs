//! The words form (`AQRV.md` §3.2) against `vectors/aqrv.json`: every case's
//! words written from its envelope and read back to it, also as free text
//! in the forms a person pastes or types; and every list of words of the
//! top-level `words` read to what it expects: corrected and opened, not
//! checking, or not AQRV words.

use aqrv::{
    Item, NoWords, NotAqrvWords, NotTextWords, NotWords, ReadWords, Size, from_words, open,
    read_text, recognise, recognise_code, recognise_file, to_words,
};
use faraday_crypto::work::Compute;
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/aqrv.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap().to_string())
        .collect()
}

/// The cases that carry their words.
fn cases_with_words() -> Vec<Value> {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    cases
        .iter()
        .filter(|c| c.get("words").is_some())
        .cloned()
        .collect()
}

/// The ways a person pastes or types a list of words, each as one text.
fn forms(words: &[String]) -> Vec<(&'static str, String)> {
    let four: Vec<&str> = words.iter().map(|w| &w[..4]).collect();
    let numbered: Vec<String> = words
        .iter()
        .enumerate()
        .map(|(i, w)| format!("{}. {w}", i + 1))
        .collect();
    let rows: Vec<String> = words
        .chunks(4)
        .enumerate()
        .map(|(r, row)| {
            let cells: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(k, w)| format!("{:>2}) {w}", r * 4 + k + 1))
                .collect();
            cells.join("   ")
        })
        .collect();
    vec![
        ("single spaces", words.join(" ")),
        ("one a line", words.join("\n")),
        ("lines of Windows", words.join("\r\n") + "\r\n"),
        ("no separators", words.concat()),
        ("first four, spaced", four.join(" ")),
        ("first four, run together", four.concat()),
        ("upper case", words.join(" ").to_uppercase()),
        ("upper case, run together", words.concat().to_uppercase()),
        ("numbered, one a line", numbered.join("\n")),
        ("numbered, four a row", rows.join("\n")),
        ("commas", words.join(", ")),
        ("tabs and spaces", format!("  {}\t", words.join(" \t "))),
        ("lines that join a word to the next", join_some_lines(words)),
    ]
}

/// Four words a line, every other line break dropped, as a field that loses
/// a pasted line break would leave it.
fn join_some_lines(words: &[String]) -> String {
    let lines: Vec<String> = words.chunks(4).map(|c| c.join(" ")).collect();
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        out.push_str(line);
        if i % 2 == 1 {
            out.push('\n');
        }
    }
    out
}

#[test]
fn every_cases_words_are_written_from_its_envelope_and_read_back() {
    let cases = cases_with_words();
    assert!(cases.len() >= 100);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let envelope = unhex(case["envelope"].as_str().unwrap());
        let words = strings(&case["words"]);
        assert_eq!(to_words(&envelope).unwrap(), words, "{name}");
        let read = from_words(&words).unwrap();
        assert_eq!(hex(&read.envelope), hex(&envelope), "{name}");
        assert!(read.corrected.is_empty(), "{name}");
    }
}

#[test]
fn every_cases_words_read_as_free_text_in_every_form() {
    for case in cases_with_words() {
        let name = case["name"].as_str().unwrap();
        let envelope = unhex(case["envelope"].as_str().unwrap());
        let words = strings(&case["words"]);
        for (form, text) in forms(&words) {
            let read = read_text(&text).unwrap_or_else(|e| panic!("{name}, {form}: {e:?}"));
            assert_eq!(hex(&read.envelope), hex(&envelope), "{name}, {form}");
            assert!(read.corrected.is_empty(), "{name}, {form}");
        }
    }
}

#[test]
fn a_32_byte_envelope_has_no_words_and_a_37_byte_one_is_never_a_qr_code() {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    for case in cases {
        let envelope = unhex(case["envelope"].as_str().unwrap());
        match recognise(&envelope).map(|h| h.size) {
            Some(Size::Tiny) => assert_eq!(to_words(&envelope), Err(NoWords::TinySize)),
            Some(Size::Words) => {
                assert_eq!(recognise_code(&envelope), None);
                assert!(recognise_file(&envelope).is_some());
            }
            Some(_) => assert!(to_words(&envelope).is_ok()),
            None => assert_eq!(to_words(&envelope), Err(NoWords::NotAnEnvelope)),
        }
    }
}

fn positions(v: &Value) -> Vec<usize> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_u64().unwrap() as usize)
        .collect()
}

/// The words read as the entry expects them: positions, corrections, words
/// and envelope.
fn check_read(name: &str, read: &ReadWords, expect: &Value) {
    assert_eq!(read.unreadable, positions(&expect["unreadable"]), "{name}");
    assert_eq!(read.wrong, positions(&expect["wrong"]), "{name}");
    let corrected: Vec<(usize, String, String)> = expect["corrected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["position"].as_u64().unwrap() as usize,
                c["input"].as_str().unwrap().to_string(),
                c["word"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let got: Vec<(usize, String, String)> = read
        .corrected
        .iter()
        .map(|c| (c.position, c.input.clone(), c.word.to_string()))
        .collect();
    assert_eq!(got, corrected, "{name}");
    assert_eq!(read.words, strings(&expect["words"]), "{name}");
    assert_eq!(
        hex(&read.envelope),
        expect["envelope"].as_str().unwrap(),
        "{name}"
    );
}

fn not_aqrv_reason(reason: &str) -> NotAqrvWords {
    if reason.contains("unused") {
        NotAqrvWords::UnusedBits
    } else if reason.contains("step") {
        NotAqrvWords::Step
    } else {
        let n = reason.split_whitespace().next().unwrap().parse().unwrap();
        NotAqrvWords::Count(n)
    }
}

/// What an entry of the top-level `words` list expects, as the reader says it.
fn expected(entry: &Value) -> Result<(), NotWords> {
    let expect = &entry["expect"];
    match expect["outcome"].as_str().unwrap() {
        "opens" => Ok(()),
        "words_do_not_check" => Err(NotWords::DoNotCheck),
        "not_aqrv_words" => Err(NotWords::NotAqrv(not_aqrv_reason(
            expect["reason"].as_str().unwrap(),
        ))),
        other => panic!("an outcome {other}"),
    }
}

#[test]
fn every_list_of_words_reads_as_it_expects_and_opens_to_its_item() {
    let v = vectors();
    let entries = v["words"].as_array().unwrap();
    assert_eq!(entries.len(), 51);
    let c = Compute::unchecked();
    for entry in entries {
        let name = entry["name"].as_str().unwrap();
        let input = strings(&entry["input"]);
        let got = from_words(&input);
        assert_eq!(
            got.as_ref().map(|_| ()).map_err(|e| *e),
            expected(entry),
            "{name}"
        );
        let Ok(read) = got else { continue };
        let expect = &entry["expect"];
        check_read(name, &read, expect);
        let passphrase = entry["passphrase"].as_str().unwrap();
        let opened = open(&c, &read.envelope, passphrase).unwrap();
        let kind = format!("0x{:02X}", opened.item.kind().unwrap() as u8);
        assert_eq!(kind, expect["kind"].as_str().unwrap(), "{name}");
        let Item::Entropy(bytes) = &opened.item else {
            panic!("{name}: the vectors' lists of words hold seeds")
        };
        assert_eq!(
            hex(bytes),
            expect["item"]["hex"].as_str().unwrap(),
            "{name}"
        );
    }
}

/// Each list given as text, one position a word and spaces between: the
/// free-text reader reads it as the list reader does.
#[test]
fn every_list_of_words_as_spaced_text_reads_as_the_list_does() {
    let v = vectors();
    for entry in v["words"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let input = strings(&entry["input"]);
        let text = input.join(" ");
        let got = read_text(&text);
        let want = from_words(&input);
        match (got, want) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "{name}"),
            (Err(NotTextWords::Words(a)), Err(b)) => assert_eq!(a, b, "{name}"),
            (got, want) => panic!("{name}: {got:?} where the list reads {want:?}"),
        }
    }
}

/// The list's words with corrections, run together: the text reader finds
/// the one reading that checks and corrects it.
#[test]
fn words_run_together_with_an_unreadable_word_are_corrected() {
    let v = vectors();
    let entry = v["words"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "words-correct-0u-1w-36")
        .unwrap()
        .clone();
    let input = strings(&entry["input"]);
    let read = read_text(&input.concat()).unwrap();
    check_read(
        "words-correct-0u-1w-36, run together",
        &read,
        &entry["expect"],
    );

    // An unreadable mark among words run together.
    let mut marked = input.clone();
    marked[29] = "?".to_string();
    let read = read_text(&marked.concat()).unwrap();
    assert_eq!(read.unreadable, [30]);
    assert_eq!(read.corrected[0].word, "academic");
}

#[test]
fn the_text_reader_refuses_what_it_cannot_read_rather_than_guess() {
    // Too many words.
    let many = "academic ".repeat(37);
    assert_eq!(
        read_text(&many),
        Err(NotTextWords::Words(NotWords::NotAqrv(NotAqrvWords::Count(
            37
        ))))
    );
    // Nothing at all.
    assert_eq!(
        read_text(" 1. 2. \n"),
        Err(NotTextWords::Words(NotWords::NotAqrv(NotAqrvWords::Count(
            0
        ))))
    );
    // A text far longer than any sheet fails at once.
    assert_eq!(
        read_text(&"acad ".repeat(10_000)),
        Err(NotTextWords::TooMany)
    );
    // A run of letters that can be cut in very many ways: every 8-letter
    // word that is two words' first four letters, run together.
    let run = "advocate".repeat(56);
    assert!(matches!(read_text(&run), Err(NotTextWords::TooMany)));
    // A letter of another script makes its run one unreadable position:
    // filled when the words are spaced, and the whole run when they are not.
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    let case = cases.iter().find(|c| c["name"] == "step-0-12w-37").unwrap();
    let mut words = strings(&case["words"]);
    words[1] = words[1].replace('k', "\u{212A}");
    let read = read_text(&words.join(" ")).unwrap();
    assert_eq!(read.unreadable, [2]);
    assert_eq!(read.corrected[0].word, "making");
    assert_eq!(
        read_text(&words.concat()),
        Err(NotTextWords::Words(NotWords::NotAqrv(NotAqrvWords::Count(
            1
        ))))
    );
}

/// The words of the 48-word case, for the paste formats below.
fn words_48() -> (Vec<String>, String) {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    let case = cases.iter().find(|c| c["name"] == "step-0-24w-53").unwrap();
    (
        strings(&case["words"]),
        case["envelope"].as_str().unwrap().to_string(),
    )
}

fn reads_to(text: &str, envelope: &str, what: &str) -> ReadWords {
    let read = read_text(text).unwrap_or_else(|e| panic!("{what}: {e:?}"));
    assert_eq!(hex(&read.envelope), envelope, "{what}");
    read
}

#[test]
fn every_numbering_style_only_separates_the_words() {
    let (words, envelope) = words_48();
    let styles: [fn(usize, &str) -> String; 8] = [
        |n, w| format!("{n} {w}"),
        |n, w| format!("{n}. {w}"),
        |n, w| format!("{n}) {w}"),
        |n, w| format!("({n}) {w}"),
        |n, w| format!("{n}: {w}"),
        |n, w| format!("#{n} {w}"),
        |n, w| format!("{n:02} {w}"),
        |n, w| format!("{n}.{w}"),
    ];
    for (i, style) in styles.iter().enumerate() {
        let items: Vec<String> = words
            .iter()
            .enumerate()
            .map(|(k, w)| style(k + 1, w))
            .collect();
        for sep in ["\n", " ", ""] {
            reads_to(&items.join(sep), &envelope, &format!("style {i}, {sep:?}"));
        }
        let four: Vec<String> = words
            .iter()
            .enumerate()
            .map(|(k, w)| style(k + 1, &w[..4]))
            .collect();
        reads_to(
            &four.join(""),
            &envelope,
            &format!("style {i}, first four glued"),
        );
    }
}

#[test]
fn tabs_crlf_no_break_and_zero_width_spaces_bullets_and_json_separate_the_words() {
    let (words, envelope) = words_48();
    reads_to(&words.join("\t"), &envelope, "tabs");
    reads_to(&words.join("\r\n"), &envelope, "CRLF");
    reads_to(&words.join("\u{A0}"), &envelope, "no-break spaces");
    reads_to(&words.join("\u{200B}"), &envelope, "zero-width spaces");
    reads_to(
        &format!("\u{FEFF}{}", words.join(" ")),
        &envelope,
        "a byte order mark",
    );
    reads_to(&words.join(" \u{2013} "), &envelope, "en dashes");
    let bullets: Vec<String> = words.iter().map(|w| format!("\u{2022} {w}")).collect();
    reads_to(&bullets.join("\n"), &envelope, "bullets");
    let quoted: Vec<String> = words.iter().map(|w| format!("\"{}\"", &w[..4])).collect();
    reads_to(
        &format!("[{}]", quoted.join(", ")),
        &envelope,
        "a JSON list",
    );
    let curly: Vec<String> = words
        .iter()
        .map(|w| format!("\u{201C}{w}\u{201D}"))
        .collect();
    reads_to(
        &curly.join("\u{FF0C}"),
        &envelope,
        "curly quotes, full-width commas",
    );
}

#[test]
fn a_grid_copied_column_by_column_reads_in_its_numbers_order() {
    let (words, envelope) = words_48();
    let mut text = String::new();
    for col in 0..4 {
        for row in 0..words.len() / 4 {
            let n = row * 4 + col;
            text.push_str(&format!("{} {}\n", n + 1, words[n]));
        }
    }
    reads_to(&text, &envelope, "column by column");
    // Numbers that are not 1 to n each once only separate: text order.
    let wrong = text.replacen("1 ", "2 ", 1);
    assert!(read_text(&wrong).is_err());
}

#[test]
fn a_hyphen_at_a_line_break_joins_a_word() {
    let (words, envelope) = words_48();
    let mut parts: Vec<String> = words.clone();
    parts[2] = format!("{}-  \n  {}", &words[2][..3], &words[2][3..]);
    parts[9] = format!("{}-\r\n{}", &words[9][..2], &words[9][2..]);
    let read = reads_to(&parts.join(" "), &envelope, "hyphenated wraps");
    assert!(read.corrected.is_empty());
}

#[test]
fn question_marks_and_accents_are_one_unreadable_position_each() {
    let (words, envelope) = words_48();
    let mut marked = words.clone();
    marked[9] = "??".to_string();
    let read = reads_to(&marked.join(" "), &envelope, "??");
    assert_eq!(read.unreadable, [10]);
    assert_eq!(read.corrected[0].input, "??");

    let at = words.iter().position(|w| w.contains('e')).unwrap();
    let mut accented = words.clone();
    accented[at] = words[at].replacen('e', "e\u{301}", 1);
    let read = reads_to(&accented.join(" "), &envelope, "a combining accent");
    assert_eq!(read.unreadable, [at + 1]);
    assert_eq!(read.corrected[0].word, words[at]);
}

#[test]
fn a_heading_pasted_with_the_words_does_not_open_silently() {
    let (words, _) = words_48();
    for heading in ["AQRV words:\n", "Argon QR Vault\n", "words "] {
        let got = read_text(&format!("{heading}{}", words.join(" ")));
        assert!(got.is_err(), "{heading:?}: {got:?}");
    }
}

/// What an entry of `words_text` expects, as the text reader says it.
fn expected_text(entry: &Value) -> Result<(), NotTextWords> {
    let expect = &entry["expect"];
    let reason = expect["reason"].as_str().unwrap_or("");
    match expect["outcome"].as_str().unwrap() {
        "opens" => Ok(()),
        "words_do_not_check" => Err(NotTextWords::Words(NotWords::DoNotCheck)),
        "not_aqrv_words" => Err(NotTextWords::Words(NotWords::NotAqrv(not_aqrv_reason(
            &reason.replacen(" positions", " words", 1),
        )))),
        "ambiguous" => Err(NotTextWords::Ambiguous),
        "too_many" => Err(NotTextWords::TooMany),
        other => panic!("an outcome {other}"),
    }
}

#[test]
fn every_text_of_words_reads_as_it_expects_and_opens_to_its_item() {
    let v = vectors();
    let entries = v["words_text"].as_array().unwrap();
    assert_eq!(entries.len(), 47);
    let c = Compute::unchecked();
    for entry in entries {
        let name = entry["name"].as_str().unwrap();
        let got = read_text(entry["text"].as_str().unwrap());
        assert_eq!(
            got.as_ref().map(|_| ()).map_err(|e| *e),
            expected_text(entry),
            "{name}"
        );
        let Ok(read) = got else { continue };
        let expect = &entry["expect"];
        check_read(name, &read, expect);
        let opened = open(&c, &read.envelope, entry["passphrase"].as_str().unwrap()).unwrap();
        let kind = format!("0x{:02X}", opened.item.kind().unwrap() as u8);
        assert_eq!(kind, expect["kind"].as_str().unwrap(), "{name}");
        let Item::Entropy(bytes) = &opened.item else {
            panic!("{name}: the vectors' texts hold seeds")
        };
        assert_eq!(
            hex(bytes),
            expect["item"]["hex"].as_str().unwrap(),
            "{name}"
        );
    }
}
