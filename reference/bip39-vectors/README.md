# BIP 39 test vectors

`vectors.json` is the test vector file of Trezor's python-mnemonic
(`https://github.com/trezor/python-mnemonic`), the BIP 39 reference
implementation vendored in `../python-mnemonic/`: for each language, lists of
entropy, mnemonic, seed and the extended private key. `vectors/gen.py` reads
it for the English entries: the entropy and the words of the seeds in the
vectors are the published ones.

The file is not the one at python-mnemonic's commit
`d4b106cdec196202d44628026fcb8fedc8ea50c1` (the vendored copy's): that one
has 10 languages and this has 12, so it is a different version, and which
commit it comes from is not recorded.

License: MIT, python-mnemonic's, in `../python-mnemonic/LICENSE`.

| File | SHA-256 |
|---|---|
| `vectors.json` | `fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8` |
