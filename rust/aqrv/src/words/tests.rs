//! The field, the check and the word list against §3.2's published values
//! and SLIP-0039's own checksum; and the correction's bound, against the
//! vectors' entries that a decoder allowed `2e + f <= 6` would read.

use super::gf::{GENERATOR, exp, mul, polymod};
use super::{CS, NotWords, WORD_LIST, WORDS, read_within};

/// (x − a)(x − a^2)…(x − a^k), coefficients highest first, its leading 1
/// included.
fn product_of_roots(k: u32) -> Vec<u16> {
    let mut g = vec![1u16];
    for i in 1..=k {
        let root = exp(i);
        let mut next = vec![0u16; g.len() + 1];
        for (j, &c) in g.iter().enumerate() {
            next[j] ^= c;
            next[j + 1] ^= mul(c, root);
        }
        g = next;
    }
    g
}

#[test]
fn the_generator_is_the_product_of_its_six_roots() {
    let g = product_of_roots(6);
    assert_eq!(g[0], 1);
    assert_eq!(g[1..], GENERATOR);
}

#[test]
fn a_generates_every_nonzero_element() {
    let mut seen = vec![false; 1024];
    for i in 0..1023 {
        seen[usize::from(exp(i))] = true;
    }
    assert!(!seen[0] && seen[1..].iter().all(|&s| s));
    assert_eq!(exp(1), 2);
    assert_eq!(exp(10), 0x009);
}

/// SLIP-0039's `rs1024_polymod`, with its published constants.
fn slip39_polymod(values: &[u16]) -> u32 {
    const GEN: [u32; 10] = [
        0xE0_E040,
        0x1C1_C080,
        0x383_8100,
        0x707_0200,
        0xE0E_0009,
        0x1C0C_2412,
        0x3808_6C24,
        0x3090_FC48,
        0x21B1_F890,
        0x3F3_F120,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 20;
        chk = ((chk & 0xF_FFFF) << 10) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

#[test]
fn at_three_check_symbols_the_check_is_slip39s_rs1024() {
    let g3 = product_of_roots(3);
    let g: [u16; 3] = g3[1..].try_into().unwrap();
    // A small generator of its own, so that the inputs repeat for anyone.
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state & 0x3FF) as u16
    };
    for len in 0..300 {
        let values: Vec<u16> = (0..len % 80).map(|_| next()).collect();
        let rem = polymod(&g, values.iter().copied());
        let packed = rem.iter().fold(0u32, |a, &r| (a << 10) | u32::from(r));
        assert_eq!(packed, slip39_polymod(&values), "{values:?}");
    }
}

#[test]
fn the_word_list_is_slip39s_byte_for_byte() {
    let hash = faraday_crypto::sha256(WORD_LIST.as_bytes());
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"
    );
    assert_eq!(WORDS.len(), 1024);
    assert_eq!((WORDS[0], WORDS[1023]), ("academic", "zero"));
    // Sorted, with first four letters unique: a word is found by them.
    assert!(WORDS.windows(2).all(|w| w[0][..4] < w[1][..4]));
}

#[test]
fn the_customization_string_is_22_symbols() {
    assert_eq!(CS, b"argon-qr-vault-1 words");
}

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/aqrv.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn words_that_do_not_check_would_decode_only_where_the_vectors_say() {
    let v = vectors();
    let entries = v["words"].as_array().unwrap();
    let mut tried = 0;
    // The lists that fail the rule, not those a correction restores to a
    // list whose bits no writer makes.
    let beyond = entries
        .iter()
        .filter(|e| e["name"].as_str().unwrap().starts_with("words-no-check-"));
    for entry in beyond {
        let would = entry["expect"]["decodes_without_the_rule"]
            .as_bool()
            .unwrap();
        let input: Vec<&str> = entry["input"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect();
        let name = entry["name"].as_str().unwrap();
        assert_eq!(read_within(&input, 4), Err(NotWords::DoNotCheck), "{name}");
        let wide = read_within(&input, 6);
        assert_eq!(!matches!(wide, Err(NotWords::DoNotCheck)), would, "{name}");
        tried += 1;
    }
    assert!(tried >= 12);
}
