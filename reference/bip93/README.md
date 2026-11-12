# BIP 93 codex32 vectors

BIP 93 ships no vector files: its vectors are prose and bullet lists in the
BIP text. The text is not kept here: `vectors.json` was extracted from the copy
of `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0093.mediawiki`
downloaded on 2026-09-18, SHA-256
`c847c6e513b64ee6ab10975690757d64a875f77c0e75866a86b733f3985784ec`. To
extract again, download the text into this folder, check its digest, and run:

    cd reference/bip93 && python3 extract.py > vectors.json

`vectors/gen.py` reads `vectors.json` for the codex32 cases of the vectors:
valid secrets of each size and strings that are refused.

License: BIP 93's header names BSD-3-Clause, and its Copyright section says
the document is licensed under the 3-clause BSD license. `extract.py` and
`vectors.json` are a script and data taken from that text.

| File | Downloaded | SHA-256 | Read by |
|---|---|---|---|
| `extract.py` | written here | `b9015466d4fcbe1a7ff66a7cbbd30d0ce802d1da333967be9f46c6621f456890` | people |
| `vectors.json` | 2026-09-18 | `9f6d9d1969072c0a635bf217a26934f7ab5d40e136c9f3d4a4d35acfb4d1447e` | `vectors/gen.py` |

`vectors.json` has four keys, each entry naming the BIP vector it came from:

- `secrets`: the unshared codex32 secrets (vectors 1, 4, 5, 6, 7 and 8), each
  with its master seed and, for vectors 1 to 5, the master node xprv. Vector 5
  also carries the identifier, payload and checksum the BIP names separately.
- `sets`: the two share sets (vectors 2 and 3): the shares the BIP publishes,
  the shares it derives from them by index, the secret they recover, the
  master seed and the xprv.
- `alternates`: the other codex32 secrets the BIP lists as equally valid
  encodings of one master seed (vectors 3 and 4); they differ only in the
  padding bits.
- `invalid`: all 55 strings the BIP refuses, grouped under the sentence that
  says why.
