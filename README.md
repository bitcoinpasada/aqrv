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
| [`AQRV.md`](AQRV.md) | the specification: the envelope (§3), the header (§4), memory steps (§5), keys, encryption and the tag (§6), false matches (§8), recognition (§9), the passphrase (§10), test vectors (§11), security analysis (§12), questions for an outside cryptographer (§13), comparison with KEF and an OpenPGP QR vault (§14) |
| [`vectors/aqrv.json`](vectors/aqrv.json) | 179 test cases, each with its inputs, every intermediate value and the expected outcome |
| [`vectors/qr-32.png`](vectors/qr-32.png), [`qr-53.png`](vectors/qr-53.png), [`qr-62.png`](vectors/qr-62.png) | the QR code of one case at each size |
| [`vectors/gen.py`](vectors/gen.py) | writes the vectors; `--check` compares without writing |
| [`vectors/check.py`](vectors/check.py) | a second reader and writer, written from the specification alone, run over every case |
| [`vectors/README.md`](vectors/README.md) | what the vectors hold, what computed them, what is not in them |
| [`reference/`](reference) | the code and data `gen.py` reads, each folder with its source, license and SHA-256: `qrcodegen` (Nayuki's QR code generator), `python-mnemonic` (Trezor's BIP 39 library), `bip39-vectors` (its test vectors) and `bip93` (codex32's text and vectors) |

## The reference implementation

A Rust library, a command line and a desktop test app are in the
[`aqrv/` folder of Faraday's repository](https://github.com/bitcoinpasada/faraday/tree/main/aqrv).
They are by the same authors as the specification, so they are not the outside
implementation the specification asks for. Downloads of the desktop test app
and the command line, for Linux and Windows on x86-64, are at
[faradayoffline.app/aqrv](https://faradayoffline.app/aqrv/#try) and on the
[aqrv-test-1 release](https://github.com/bitcoinpasada/faraday/releases/tag/aqrv-test-1),
with `SHA256SUMS`. It is a test release: use it with test data only.

## Checking the vectors

`gen.py` needs the Python packages `argon2-cffi` and `cryptography`;
`check.py` needs `cryptography` (a version with Argon2id) and, for the QR
pictures, `zxingcpp`, Pillow and the `zbarimg` program, each skipped with a
note if missing. From the repository root:

    python3 -I -B vectors/gen.py --check    # the files are what gen.py makes
    python3 -I -B vectors/check.py          # the second reader; --no-qr skips the decoders

The run takes about 40 seconds and up to 1 GiB of memory.

## Comments

Comments go in this repository's issues, one issue for each point. A reply to
a question of §13 of the specification names its number.

## License

MIT, in [`LICENSE`](LICENSE). Each folder of `reference/` is another project's
code or text under the license its README names.
