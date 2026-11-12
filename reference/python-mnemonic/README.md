# python-mnemonic, vendored

Trezor's BIP 39 reference implementation, copied unchanged, with only its English word list (the one `vectors/gen.py` uses). `vectors/gen.py`
imports it (`mnemonic`) to turn the entropy of the seeds in the vectors into words.

Source: `https://github.com/trezor/python-mnemonic`, tag `v0.21`, commit
`d4b106cdec196202d44628026fcb8fedc8ea50c1`, folder `src/mnemonic/` (of `wordlist/`, `english.txt` only) and
`LICENSE`. Fetched with `git clone` at that tag. The tag is not signed:
what pins the copy is the commit hash and the digests below.

License: MIT, in `LICENSE` (Copyright (c) 2013-2016 Pavol Rusnak).

SHA-256 of every file, so a change to the copy is visible:

| File | SHA-256 |
|---|---|
| `LICENSE` | `d5e3c7c62a84e80073201e2f6e5130e9e6804fa05f8ac4f8b26a13c7d3969697` |
| `mnemonic/__init__.py` | `c6524bc6498b80de332bf58d100d3aec11042fbb559085aa0bc25955b2eaf68d` |
| `mnemonic/mnemonic.py` | `42daf1fb4f3b43eb40284add75d832e384bbe3aaa6d00ae68c8850b8a0a6d75b` |
| `mnemonic/wordlist/english.txt` | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |
