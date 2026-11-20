# Argon QR Vault (AQRV)

The Argon QR Vault (AQRV) is a proposed open format for one small secret
encrypted under a passphrase with Argon2id, small enough for a 29 × 29 QR
code, and a 12-word seed for a 25 × 25 one. The name says it uses Argon2id and
is a vault in a QR code.

This is a draft for outside review. It is an own construction of Faraday's
authors, not a published standard, and no one outside them has reviewed it:
no cryptographer, no second implementation. Faraday's applications do not use
it.

## What is where

| Path | What it holds |
|---|---|
| [`AQRV.md`](AQRV.md) | the specification: the envelope (§3), the words form (§3.2), the header (§4), memory steps (§5), keys, encryption and the tag (§6), false matches (§8), recognition (§9), the passphrase (§10), test vectors (§11), security analysis (§12), questions for an outside cryptographer (§13), comparison with KEF and an OpenPGP QR vault (§14) |
| [`vectors/aqrv.json`](vectors/aqrv.json) | 195 test cases, each with its inputs, every intermediate value and the expected outcome, the words of each envelope a sheet of words can hold, 51 entries of words to read: corrected, not checking, not AQRV words, and named by their first letters, and 47 texts of words to read as pasted: separators, numbers, words run together, unreadable runs, ambiguous and too many |
| [`vectors/qr-32.png`](vectors/qr-32.png), [`qr-53.png`](vectors/qr-53.png), [`qr-62.png`](vectors/qr-62.png) | the QR code of one case at each size |
| [`vectors/gen.py`](vectors/gen.py) | writes the vectors; `--check` compares without writing |
| [`vectors/check.py`](vectors/check.py) | a second reader and writer, written from the specification alone, run over every case |
| [`vectors/README.md`](vectors/README.md) | what the vectors hold, what computed them, what is not in them |
| [`reference/`](reference) | the code and data `gen.py` reads, each folder with its source, license and SHA-256: `qrcodegen` (Nayuki's QR code generator), `python-mnemonic` (Trezor's BIP 39 library), `bip39-vectors` (its test vectors), `python-shamir-mnemonic` (the word list of Trezor's SLIP-39 library) and `bip93` (codex32's text and vectors) |

## The reference implementation

A Rust library, a command line and a desktop test app are in [`rust/`](rust),
and the fuzz targets of the library in [`fuzz/`](fuzz). They are by the same
authors as the specification, so they are not the outside implementation the
specification asks for. They are for testing with test data only.

| Crate | What it is |
|---|---|
| [`rust/aqrv`](rust/aqrv) | the library: the format and nothing else (seal and open, at 32, 37, 53 and 62 bytes), the words form (§3.2: writing, reading with correction, and a reader of words pasted or typed as free text), and a copy of SLIP-0039's word list (`src/wordlist.txt`) |
| [`rust/aqrv-cli`](rust/aqrv-cli) | the command line, `aqrv`: `make --words` prints a code's words, `open --words` reads them from a file, standard input or `--text` |
| [`rust/aqrv-app`](rust/aqrv-app) | the app's screens, drawn with Faraday's UI crates, and its own strings table (`src/strings.rs`); a made code shows its words with Copy, and Open reads pasted or typed words |
| [`rust/aqrv-desktop`](rust/aqrv-desktop) | the desktop program, `argon-qr-vault`, in a window |

### Faraday, and one commit of it

The crates use Faraday's own crates (`faraday-crypto`, `faraday-bip`,
`faraday-text`, `faraday-codec`, `faraday-files`, `faraday-ui`,
`faraday-draw`, `faraday-shell-api`, `faraday-window`) as git dependencies on
`https://github.com/bitcoinpasada/faraday`, all at one commit:

    0849ae18dac00c54e1f1d34051c26fd6a0bcdc82

It is written in `rust/Cargo.toml` (`[workspace.dependencies]`) and, for the
fuzz workspace, in `fuzz/Cargo.toml` (`faraday-crypto`). To move to another
commit, change `rev` in those two files, run `cargo update` in `rust/` and in
`fuzz/` (this changes each `Cargo.lock`), then build and test as below.

The cost of this: the app follows Faraday's internal crates by a pinned
commit, with no promise that their interfaces stay the same. A new commit may
need changes here, and an old one is what stays buildable. Faraday does not
publish these crates to crates.io.

### Building and testing

`rust-toolchain.toml` names Faraday's own toolchain (Rust 1.97.0); cargo
installs it. The lock files are committed; use `--locked`.

    cd rust
    cargo build --locked
    cargo test --locked
    cargo clippy --locked --all-targets -- -D warnings
    cargo fmt --check

The fuzz workspace is its own (`fuzz/`, with the dated nightly in
`fuzz/rust-toolchain.toml`, `cargo install cargo-fuzz --locked`):

    cd fuzz
    cargo fuzz build
    cargo fuzz run aqrv_recognise     # also aqrv_text, aqrv_item, aqrv_envelope, aqrv_open

`fuzz/dict/aqrv_recognise.dict` is the dictionary of `aqrv_recognise`
(`-dict=dict/aqrv_recognise.dict`); `fuzz/corpus/aqrv_*/` are the seeds, made
from the vectors.

The tests read this repository's own `vectors/aqrv.json`: every case, the words of each case that has them, and the 51 lists of words. `vectors/diff.py`
runs the library and `check.py`'s second reader over many generated codes
(`python3 -I -B vectors/diff.py --seed 1 --rounds 3`).

### The four programs

| Program | Package and binary | Output name |
|---|---|---|
| Argon QR Vault for Linux | `aqrv-desktop`, `argon-qr-vault` | `argon-qr-vault` |
| Argon QR Vault for Windows | `aqrv-desktop`, `argon-qr-vault`, target `x86_64-pc-windows-gnu` | `argon-qr-vault.exe` |
| Argon QR Vault command line for Linux | `aqrv-cli`, `aqrv` | `aqrv` |
| Argon QR Vault command line for Windows | `aqrv-cli`, `aqrv`, target `x86_64-pc-windows-gnu` | `aqrv.exe` |

Each is `cargo build --release --locked -p PACKAGE --bin BINARY` (add
`--target x86_64-pc-windows-gnu` for Windows, with mingw-w64 installed). The
release downloads were built in Faraday's build containers (Debian 11, so
that the Linux binary needs glibc 2.31 or older; mingw-w64 for Windows), with
paths remapped and symbols stripped; this repository does not hold those
containers, so a plain build here is a test build, not the same file.

### The release "Argon QR Vault test 1"

Its downloads, for Linux and Windows on x86-64, are on the
[aqrv-test-1 release](https://github.com/bitcoinpasada/faraday/releases/tag/aqrv-test-1)
of Faraday's repository and at
[faradayoffline.app/aqrv](https://faradayoffline.app/aqrv/#try), with
`SHA256SUMS`. It is a test release: use it with test data only.

It cannot be rebuilt from this repository. Its tag `aqrv-test-1` is in
Faraday's repository (commit `d97d7ab14`), and its four programs, with
`SHA256SUMS`, were built there in Faraday's containers from the sources of
that commit. This repository carries a later state of the code, against
a later Faraday commit, and has not got those containers, so its binaries
differ from the release's and the checksums do not match. To rebuild the
release itself, check out that tag in Faraday's repository and follow
`docs/DEVELOPING.md` there ("Reproducing a release").

## Checking the vectors

`gen.py` needs the Python packages `argon2-cffi` and `cryptography`;
`check.py` needs `cryptography` (a version with Argon2id) and, for the QR
pictures, `zxingcpp`, Pillow and the `zbarimg` program, and for a second
decoding of the words `reedsolo`, each skipped with a note if missing. From
the repository root:

    python3 -I -B vectors/gen.py --check    # the files are what gen.py makes
    python3 -I -B vectors/check.py          # the second reader; --no-qr skips the decoders
    uv run --no-project --with cryptography --with reedsolo python3 -I -B vectors/check.py --no-qr

The run takes about 40 seconds and up to 1 GiB of memory.

## Comments

Comments go in this repository's issues, one issue for each point. A reply to
a question of §13 of the specification names its number.

## License

MIT, in [`LICENSE`](LICENSE). Each folder of `reference/` is another project's
code or text under the license its README names.
