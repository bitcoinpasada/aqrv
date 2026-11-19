# python-shamir-mnemonic word list, vendored

The 1024-word list of SLIP-0039, copied unchanged from Trezor's SLIP-0039
reference implementation, with its license. `vectors/gen.py` reads it for the
words form of `AQRV.md` §3.2 and stops if its SHA-256 differs from the one
below. The list is byte for byte the `slip-0039/wordlist.txt` of the SLIP
itself.

Source: `https://github.com/trezor/python-shamir-mnemonic`, commit
`4c63da0a50696e58b48f300737c4b540928d134c`, its `wordlist.txt` and `LICENSE`.
Downloaded on 2026-11-19. What pins the copy is the commit hash and the
digests below.

License: MIT, in `LICENSE` (Copyright 2019 SatoshiLabs).

| File | Downloaded | SHA-256 | Read by |
|---|---|---|---|
| `LICENSE` | 2026-11-19 | `332f92f7f90a1c957b473b902a5daf39ad5eb179d8828e0304b4c40faa0123c0` | people |
| `wordlist.txt` | 2026-11-19 | `bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3` | `vectors/gen.py` |
