//! The `vectors` command: runs the published test vectors (`AQRV.md` §11)
//! against the library. Everything it reads is public test data, so it holds
//! no secret of the person using the tool.

use aqrv::{
    Item, Kind, NotAqrvWords, NotOpened, NotWords, Refused, Size, Step, from_words, open,
    recognise, seal, to_words,
};
use faraday_bip::json::{self, Value};
use faraday_crypto::work::Compute;
use faraday_text::Text;

use crate::cli::{Args, Run, SIZE_NUMBERS, fail, io_fail, parse, unhex, usage};

/// The default place of the vectors, from the repository's root.
const VECTORS: &str = "vectors/aqrv.json";

/// What the 512 MiB and 1 GiB cases start at.
const LARGE_KIB: u64 = 524_288;

pub fn vectors(c: &Compute, args: &Args) -> Run {
    let p = parse(args, &["--case"], &["--skip-large"])?;
    let path = match p.positional.as_slice() {
        [] => VECTORS,
        [one] => one.as_str(),
        _ => return Err(usage("vectors takes one file")),
    };
    let text = std::fs::read_to_string(path).map_err(|e| io_fail(path, &e))?;
    let file = json::parse(&text).map_err(|_| fail(74, &format!("{path} is not JSON")))?;
    let cases = file
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| fail(74, &format!("{path} has no cases")))?;
    let only = p.value("--case");
    if let Some(name) = only
        && !cases.iter().any(|case| text_of(case, "name") == name)
    {
        return Err(usage(&format!("no case named {name}")));
    }
    let (mut agree, mut differ) = (0usize, 0usize);
    let mut tally = |name: &str, result: Result<(), String>| match result {
        Ok(()) => {
            agree += 1;
            println!("agrees {name}");
        }
        Err(why) => {
            differ += 1;
            println!("differs {name}: {why}");
        }
    };
    for case in cases {
        let name = text_of(case, "name");
        if only.is_some_and(|n| n != name) {
            continue;
        }
        let large = case
            .get("memory_kib")
            .and_then(Value::as_u64)
            .is_some_and(|k| k >= LARGE_KIB);
        if p.has("--skip-large") && large {
            println!("skipped {name}");
            continue;
        }
        tally(name, run_case(c, case));
    }
    if only.is_none() {
        let refusals = file.get("writer_refuses").and_then(Value::as_array);
        for entry in refusals.unwrap_or(&[]) {
            let name = format!("writer refuses {}", text_of(entry, "reason"));
            tally(&name, run_refusal(c, entry));
        }
        let lists = file.get("words").and_then(Value::as_array);
        for entry in lists.unwrap_or(&[]) {
            tally(text_of(entry, "name"), run_words(c, entry));
        }
    }
    println!("{} agree, {} differ", agree, differ);
    if differ > 0 {
        return Err(fail(5, &format!("{differ} vectors differ")));
    }
    Ok(())
}

fn text_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn run_refusal(c: &Compute, entry: &Value) -> Result<(), String> {
    // An entry with a size and an item is refused at that size.
    if let (Some(size), Some(item)) = (entry.get("size").and_then(Value::as_u64), entry.get("item"))
    {
        let size = Size::of_len(size as usize).ok_or("a size the library does not know")?;
        let got = seal(
            c,
            &expected_item(item)?,
            "pass",
            Step::Mib64,
            size,
            &mut |_| unreachable!("a refusal comes before any draw"),
        );
        return match got {
            Err(Refused::TooLong | Refused::KindNotHeld) => Ok(()),
            _ => Err("written".into()),
        };
    }
    for number in SIZE_NUMBERS {
        let size = Size::of_len(number).ok_or("a size the library does not know")?;
        let item = Item::Codex32(Text::of(text_of(entry, "string")));
        let got = seal(c, &item, "pass", Step::Mib64, size, &mut |_| {
            unreachable!("a refusal comes before any draw")
        });
        // The 32- and 37-byte sizes do not hold the kind, so it refuses that first.
        let right = match size {
            Size::Tiny | Size::Words => matches!(got, Err(Refused::KindNotHeld)),
            _ => matches!(got, Err(Refused::Codex32(_))),
        };
        if !right {
            return Err(format!("written at {number} bytes"));
        }
    }
    Ok(())
}

fn expected_item(item: &Value) -> Result<Item, String> {
    let bytes = || unhex(text_of(item, "hex")).ok_or("hex");
    Ok(match text_of(item, "type") {
        "entropy" => Item::Entropy(bytes()?.into()),
        "raw_key" => {
            let key: [u8; 32] = bytes()?.try_into().map_err(|_| "a key of another length")?;
            Item::RawKey(key.into())
        }
        "passphrase" => Item::Passphrase(Text::of(text_of(item, "text"))),
        "note" => Item::Note(Text::of(text_of(item, "text"))),
        "codex32" => Item::Codex32(Text::of(text_of(item, "string"))),
        other => return Err(format!("an item of type {other}")),
    })
}

/// The kind and the bytes or text of an item, to compare two.
fn shown(item: &Item) -> (Option<Kind>, Vec<u8>) {
    let bytes = match item {
        Item::Entropy(b) => b.to_vec(),
        Item::RawKey(k) => k.to_vec(),
        Item::Passphrase(t) | Item::Note(t) | Item::Codex32(t) => t.as_bytes().to_vec(),
    };
    (item.kind(), bytes)
}

/// §11: a case opens to what it says and seals again to its envelope, does
/// not open, or is not recognised.
fn run_case(c: &Compute, case: &Value) -> Result<(), String> {
    let envelope = unhex(text_of(case, "envelope")).ok_or("the envelope is not hex")?;
    let passphrase = text_of(case, "passphrase");
    let expect = case.get("expect").ok_or("no expectation")?;
    if let Some(words) = case.get("words") {
        let words = strings(words)?;
        if to_words(&envelope).map_err(|e| format!("no words: {e:?}"))? != words {
            return Err("other words".into());
        }
        match from_words(&words) {
            Ok(read) if read.envelope == envelope && read.corrected.is_empty() => {}
            _ => return Err("the words do not read back to the envelope".into()),
        }
    }
    match text_of(expect, "outcome") {
        "opens" => {
            let opened = open(c, &envelope, passphrase).map_err(|e| format!("{e:?}"))?;
            let want = expected_item(expect.get("item").ok_or("no item")?)?;
            if shown(&opened.item) != shown(&want) {
                return Err("another item".into());
            }
            let mut draws = vec![unhex(text_of(case, "salt")).ok_or("salt")?];
            if let Some(fill) = case.get("last_byte_fill").and_then(Value::as_str) {
                let fill = u8::from_str_radix(fill.trim_start_matches("0x"), 16)
                    .map_err(|_| "last_byte_fill")?;
                draws.push(vec![fill]);
            }
            let padding = unhex(text_of(case, "padding")).ok_or("padding")?;
            if !padding.is_empty() {
                draws.push(padding);
            }
            draws.reverse();
            let mut wrong = false;
            let mut random = |buf: &mut [u8]| match draws.pop() {
                Some(next) if next.len() == buf.len() => buf.copy_from_slice(&next),
                _ => wrong = true,
            };
            let sealed = seal(
                c,
                &want,
                passphrase,
                opened.header.step,
                opened.header.size,
                &mut random,
            )
            .map_err(|e| format!("sealing again: {e:?}"))?;
            if wrong || !draws.is_empty() {
                return Err("the draws do not fit".into());
            }
            if sealed != envelope {
                return Err("sealing again gives another envelope".into());
            }
            Ok(())
        }
        "does_not_open" => match open(c, &envelope, passphrase) {
            Err(NotOpened::NoTag | NotOpened::Layout(..)) => Ok(()),
            Err(other) => Err(format!("{other:?}")),
            Ok(_) => Err("it opens".into()),
        },
        "not_recognised" => match open(c, &envelope, passphrase) {
            Err(NotOpened::NotRecognised) if recognise(&envelope).is_none() => Ok(()),
            _ => Err("it is recognised".into()),
        },
        other => Err(format!("an outcome {other}")),
    }
}

fn strings(v: &Value) -> Result<Vec<&str>, String> {
    let all = v.as_array().ok_or("not a list")?;
    all.iter()
        .map(|w| w.as_str().ok_or_else(|| "not a string".to_string()))
        .collect()
}

fn positions(v: Option<&Value>) -> Vec<usize> {
    let all = v.and_then(Value::as_array).unwrap_or(&[]);
    all.iter()
        .filter_map(Value::as_u64)
        .map(|p| p as usize)
        .collect()
}

/// §3.2: a list of words reads as it expects: corrected and opened to its
/// item, not checking, or not AQRV words for its reason.
fn run_words(c: &Compute, entry: &Value) -> Result<(), String> {
    let input = strings(entry.get("input").ok_or("no input")?)?;
    let expect = entry.get("expect").ok_or("no expectation")?;
    let reason = text_of(expect, "reason");
    let got = from_words(&input);
    let read = match (text_of(expect, "outcome"), got) {
        ("opens", Ok(read)) => read,
        ("words_do_not_check", Err(NotWords::DoNotCheck)) => return Ok(()),
        ("not_aqrv_words", Err(NotWords::NotAqrv(why))) => {
            let right = match why {
                NotAqrvWords::Count(n) => reason.starts_with(&format!("{n} words")),
                NotAqrvWords::UnusedBits => reason.contains("unused"),
                NotAqrvWords::Step => reason.contains("step"),
            };
            return if right {
                Ok(())
            } else {
                Err(format!("{why:?}"))
            };
        }
        (want, got) => return Err(format!("{:?} where {want} is expected", got.map(|_| ()))),
    };
    let corrected: Vec<(usize, &str, &str)> = expect
        .get("corrected")
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .map(|x| {
            let at = x.get("position").and_then(Value::as_u64).unwrap_or(0) as usize;
            (at, text_of(x, "input"), text_of(x, "word"))
        })
        .collect();
    let got: Vec<(usize, &str, &str)> = read
        .corrected
        .iter()
        .map(|x| (x.position, x.input.as_str(), x.word))
        .collect();
    if read.unreadable != positions(expect.get("unreadable"))
        || read.wrong != positions(expect.get("wrong"))
        || got != corrected
    {
        return Err("other corrections".into());
    }
    if read.words != strings(expect.get("words").ok_or("no words")?)? {
        return Err("other words".into());
    }
    if unhex(text_of(expect, "envelope")) != Some(read.envelope.clone()) {
        return Err("another envelope".into());
    }
    let opened =
        open(c, &read.envelope, text_of(entry, "passphrase")).map_err(|e| format!("{e:?}"))?;
    let want = expected_item(expect.get("item").ok_or("no item")?)?;
    if shown(&opened.item) != shown(&want) {
        return Err("another item".into());
    }
    Ok(())
}
