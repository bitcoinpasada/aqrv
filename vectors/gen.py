#!/usr/bin/env python3
"""Writes the test vectors of the Argon QR Vault (AQRV) (AQRV.md §11).

    python3 -I -B vectors/gen.py            # writes aqrv.json, qr-32.png, qr-53.png, qr-62.png
    python3 -I -B vectors/gen.py --check    # compares, writes nothing

Libraries Faraday's authors did not write: argon2-cffi (Argon2id), Python's
hmac and hashlib (HMAC-SHA-256, HKDF-Expand, SHA-256, SHAKE-256), PyCA
cryptography (ChaCha20, AES-GCM, and an HKDF-Expand to cross-check the
hand-written one), Nayuki's qrcodegen (reference/qrcodegen) for the
QR code, and SLIP-0039's word list (reference/python-shamir-mnemonic) for the words. Nothing here is random: every passphrase, salt, item and padding is
fixed by the script, so a second run writes the same bytes.

Every case is also read back by `read` below, a plain reading of §6 and §9, and
the script stops if any answer differs from the one it writes. That reader is
the script's own check, not an implementation to ship.
"""
import argparse
import hashlib
import hmac
import itertools
import json
import os
import re
import struct
import sys
import time
import unicodedata
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "reference", "qrcodegen"))
sys.path.insert(0, os.path.join(ROOT, "reference", "python-mnemonic"))

from argon2.low_level import Type, hash_secret_raw  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand  # noqa: E402
from mnemonic import Mnemonic  # noqa: E402
from qrcodegen import QrCode, QrSegment  # noqa: E402

# ---------------------------------------------------------------- the format

STEPS = {0: 65536, 1: 131072, 2: 262144, 3: 524288, 4: 1048576}  # KiB
LABEL_ENC = b"argon-qr-vault-1 enc"
LABEL_MAC = b"argon-qr-vault-1 mac"
SIZES = {32: (16, 4), 37: (16, 4), 53: (32, 4), 62: (37, 8)}  # N -> (room r, tag length t)
SALT_LEN = {32: 11, 37: 16, 53: 16, 62: 16}  # N -> salt bytes

KINDS = [  # kind, name, item bytes or None
    (0x10, "BIP-39 entropy, 12 words", 16),
    (0x14, "BIP-39 entropy, 15 words", 20),
    (0x18, "BIP-39 entropy, 18 words", 24),
    (0x1C, "BIP-39 entropy, 21 words", 28),
    (0x20, "BIP-39 entropy, 24 words", 32),
    (0x30, "a codex32 string", None),
    (0x40, "a BIP-39 passphrase", None),
    (0x41, "a note", None),
    (0x50, "a raw 32-byte key", 32),
]
KIND_NAME = {k: n for k, n, _ in KINDS}
ALL_KINDS = [k for k, _, _ in KINDS]
KINDS_AT = {32: [0x10, 0x40, 0x41], 37: [0x10, 0x40, 0x41], 53: ALL_KINDS, 62: ALL_KINDS}  # the kinds a size tests
ENTROPY_LEN = {k: b for k, _, b in KINDS if k in (0x10, 0x14, 0x18, 0x1C, 0x20)}

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CODEX_BYTES = {0: 16, 1: 20, 2: 24, 3: 28, 4: 32}
CODEX_C = {0: 26, 1: 32, 2: 39, 3: 45, 4: 52}
THRESHOLDS = {CHARSET.index(ch): ch for ch in "023456789"}

MS32_CONST = 0x10CE0795C2FD1E62A
MS32_GEN = [
    0x19DC500CE73FDE210,
    0x1BFAE00DEF77FE529,
    0x1FBD920FFFE7BEE52,
    0x1739640BDEEE3FDAD,
    0x07729A039CFC75F5A,
]


def ms32_polymod(values):  # BIP 93, copied
    residue = 0x23181B3
    for v in values:
        b = residue >> 60
        residue = (residue & 0x0FFFFFFFFFFFFFFF) << 5 ^ v
        for i in range(5):
            residue ^= MS32_GEN[i] if ((b >> i) & 1) else 0
    return residue


def ms32_checksum(data):  # BIP 93 ms32_create_regular_checksum, copied
    polymod = ms32_polymod(list(data) + [0] * 13) ^ MS32_CONST
    return [(polymod >> 5 * (12 - i)) & 31 for i in range(13)]


def hx(b):
    return bytes(b).hex()


def nfc(text):
    return unicodedata.normalize("NFC", text)


# ------------------------------------------------------------- primitives

_derive_cache = {}


def hkdf_expand(prk, info):
    out = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()  # RFC 5869 §2.3, L = 32
    check = HKDFExpand(hashes.SHA256(), 32, info).derive(prk)
    assert out == check
    return out


def chacha20_stream(key, n):  # RFC 8439 §2.4: counter 0, nonce twelve zero bytes
    enc = Cipher(algorithms.ChaCha20(key, b"\x00" * 16), mode=None).encryptor()
    return enc.update(b"\x00" * n)


def derive(passphrase, salt, step):
    pw = nfc(passphrase).encode("utf-8")
    key = (pw, bytes(salt), step)
    if key not in _derive_cache:
        prk = hash_secret_raw(pw, bytes(salt), time_cost=3, memory_cost=STEPS[step],
                              parallelism=4, hash_len=32, type=Type.ID, version=19)
        k_enc = hkdf_expand(prk, LABEL_ENC)
        k_mac = hkdf_expand(prk, LABEL_MAC)
        _derive_cache[key] = dict(pw=pw, prk=prk, k_enc=k_enc, k_mac=k_mac,
                                  keystream=chacha20_stream(k_enc, 37))
    return _derive_cache[key]


def tag_message(header, n, salt, kind, c):
    return bytes([header, n]) + bytes(salt) + bytes([kind]) + bytes(c)


def tag(k_mac, header, n, salt, kind, c, t):
    return hmac.new(k_mac, tag_message(header, n, salt, kind, c), hashlib.sha256).digest()[:t]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ------------------------------------------------------------- the reader


def parse_item(kind, p, r):
    """Reads P by kind's layout. Returns (item dict, None) or (None, why)."""
    if kind in ENTROPY_LEN:
        return {"type": "entropy", "hex": hx(p[:ENTROPY_LEN[kind]])}, None
    if kind == 0x50:
        return {"type": "raw_key", "hex": hx(p[:32])}, None
    if kind in (0x40, 0x41):
        n = p[0]
        if n < 1 or n > r - 1:
            return None, "len %d is outside 1 to %d" % (n, r - 1)
        try:
            text = bytes(p[1:1 + n]).decode("utf-8")
        except UnicodeDecodeError:
            return None, "the text is not valid UTF-8"
        return {"type": "passphrase" if kind == 0x40 else "note", "text": text}, None
    assert kind == 0x30
    size = p[0] >> 5
    if size > 4:
        return None, "codex32 size %d is reserved" % size
    c = CODEX_C[size]
    nbits = 34 + 5 * c
    nbytes = (nbits + 7) // 8
    if nbytes > r:
        return None, "codex32 size %d needs %d bytes, the room is %d" % (size, nbytes, r)
    bits = int.from_bytes(p[:nbytes], "big") >> (nbytes * 8 - nbits)
    upper = (bits >> (nbits - 4)) & 1
    pos = nbits - 4
    pos -= 5
    threshold = (bits >> pos) & 31
    ident = []
    for _ in range(4):
        pos -= 5
        ident.append((bits >> pos) & 31)
    pos -= 5
    index = (bits >> pos) & 31
    payload = []
    for _ in range(c):
        pos -= 5
        payload.append((bits >> pos) & 31)
    assert pos == 0
    if threshold not in THRESHOLDS and threshold != CHARSET.index("0"):
        return None, "codex32 threshold value %d is not 0 or 2 to 9" % threshold
    if threshold == CHARSET.index("0") and index != CHARSET.index("s"):
        return None, "codex32 threshold 0 with an index other than s"
    data = [threshold] + ident + [index] + payload
    s = "ms1" + "".join(CHARSET[v] for v in data + ms32_checksum(data))
    if upper:
        s = s.upper()
    return {"type": "codex32", "string": s, "is_secret": index == CHARSET.index("s")}, None


def read(env, passphrase):
    """§9 then §6 reading. Returns a dict with outcome and, when it opens, kind and item."""
    n = len(env)
    if n not in SIZES or not (0xF8 <= env[0] <= 0xFC):
        return {"outcome": "not_recognised"}
    r, t = SIZES[n]
    sl = SALT_LEN[n]
    step = env[0] & 7
    salt, c, stored = env[1:1 + sl], env[1 + sl:1 + sl + r], env[1 + sl + r:]
    d = derive(passphrase, salt, step)
    hits = [k for k in KINDS_AT[n] if tag(d["k_mac"], env[0], n, salt, k, c, t) == stored]
    if not hits:
        return {"outcome": "does_not_open", "why": "no_tag_matches"}
    assert len(hits) == 1
    p = xor(c, d["keystream"][:r])
    item, why = parse_item(hits[0], p, r)
    if item is None:
        return {"outcome": "does_not_open", "why": "format", "kind": hits[0], "detail": why}
    return {"outcome": "opens", "kind": hits[0], "item": item}


# ------------------------------------------------------------- the words form (§3.2)

WORDLIST_PATH = os.path.join(ROOT, "reference", "python-shamir-mnemonic", "wordlist.txt")
WORDLIST_SHA256 = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"
WORDS_CS = b"argon-qr-vault-1 words"
WORDS_CHECK = 6
WORDS_BOUND = 4  # a correction is accepted only if 2e + f <= 4
GF_POLY = 0x409  # x^10 + x^3 + 1
WORDS_GENERATOR = [1, 0x7E, 0x83, 0x34F, 0x110, 0x9E, 0x82]
WORDS_TABLE = {37: (291, 30, 9), 53: (419, 42, 1), 62: (491, 50, 9)}  # N -> bits, data words, unused bits


def _wordlist():
    data = open(WORDLIST_PATH, "rb").read()
    assert hashlib.sha256(data).hexdigest() == WORDLIST_SHA256, "the SLIP-0039 word list differs"
    words = data.decode("ascii").split("\n")
    assert words[-1] == "" and len(words) == 1025
    words = words[:-1]
    assert all(w.isalpha() and w.islower() and 4 <= len(w) <= 8 for w in words)
    assert len({w[:4] for w in words}) == 1024 and len(set(words)) == 1024
    assert not any(a != b and b.startswith(a) for a in words for b in words if a[:4] == b[:4])
    letters = "abcdefghijklmnopqrstuvwxyz"
    have = set(words)
    for w in words:  # SLIP-0039: no two words one edit apart, a swap of neighbours counting as one
        near = set()
        for i in range(len(w) + 1):
            for ch in letters:
                near.add(w[:i] + ch + w[i:])
        for i in range(len(w)):
            near.add(w[:i] + w[i + 1:])
            for ch in letters:
                near.add(w[:i] + ch + w[i + 1:])
        for i in range(len(w) - 1):
            near.add(w[:i] + w[i + 1] + w[i] + w[i + 2:])
        near.discard(w)
        assert not (near & have), (w, near & have)
    return words


WORDS = _wordlist()
WORD_BY_PREFIX = {w[:4]: i for i, w in enumerate(WORDS)}

GF_EXP = [0] * 2046
GF_LOG = [0] * 1024
_x = 1
for _i in range(1023):
    GF_EXP[_i] = _x
    assert _i == 0 or _x != 1, "2 is not primitive"
    GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x400:
        _x ^= GF_POLY
assert _x == 1 and len(set(GF_EXP[:1023])) == 1023
for _i in range(1023, 2046):
    GF_EXP[_i] = GF_EXP[_i - 1023]


def gmul(a, b):
    return 0 if a == 0 or b == 0 else GF_EXP[GF_LOG[a] + GF_LOG[b]]


def ginv(a):
    assert a
    return GF_EXP[1023 - GF_LOG[a]]


def _gmul_slow(a, b):  # the field's own definition, to check the tables
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x400:
            a ^= GF_POLY
    return r


def gen_poly(r):
    g = [1]
    for i in range(1, r + 1):
        root = GF_EXP[i]
        ng = g + [0]
        for j in range(len(g)):
            ng[j + 1] ^= gmul(g[j], root)
        g = ng
    return g


_GEN = {r: gen_poly(r) for r in (3, 6)}


def polymod_r(values, r):
    """The remainder mod g(x) of 1 followed by values, as r symbols, highest first."""
    g = _GEN[r]
    reg = [0] * (r - 1) + [1]
    for v in values:
        top = reg[0]
        reg = reg[1:] + [v]
        if top:
            for j in range(r):
                reg[j] ^= gmul(top, g[j + 1])
    return reg


def rs1024_polymod(values):  # SLIP-0039 rs1024_polymod, copied
    GEN = (0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009, 0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120)
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xFFFFF) << 10 ^ v
        for i in range(10):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _words_selftest():
    for a in range(0, 1024, 7):
        for b in range(0, 1024, 11):
            assert gmul(a, b) == _gmul_slow(a, b)
    assert _GEN[6] == WORDS_GENERATOR, [hex(c) for c in _GEN[6]]
    for i in range(400):
        stream = shake("words polymod %d" % i, 120)
        m = 1 + stream[0] % 56
        data = [((stream[1 + 2 * k] << 8) | stream[2 + 2 * k]) & 1023 for k in range(m)]
        for cs in (b"shamir", WORDS_CS):
            reg = polymod_r(list(cs) + data, 3)
            assert ((reg[0] << 20) | (reg[1] << 10) | reg[2]) == rs1024_polymod(list(cs) + data)
            p = rs1024_polymod(list(cs) + data + [0, 0, 0]) ^ 1
            slip = [(p >> 10 * k) & 1023 for k in reversed(range(3))]
            assert words_check(data, 3, cs) == slip
            assert polymod_r(list(cs) + data + words_check(data, 6, cs), 6) == [0] * 5 + [1]
    for n, (bits, m, unused) in WORDS_TABLE.items():
        assert bits == 8 * n - 5 and m == (bits + 9) // 10 and unused == 10 * m - bits
        assert m + WORDS_CHECK == {37: 36, 53: 48, 62: 56}[n]


def words_check(data, r=WORDS_CHECK, cs=WORDS_CS):
    reg = polymod_r(list(cs) + list(data) + [0] * r, r)
    reg[-1] ^= 1
    return reg


def words_valid(values):
    return polymod_r(list(WORDS_CS) + list(values), WORDS_CHECK) == [0] * (WORDS_CHECK - 1) + [1]


def data_words(env):
    n = len(env)
    bits, m, unused = WORDS_TABLE[n]
    v = int.from_bytes(env, "big")
    assert v >> bits == 0b11111
    v = (v & ((1 << bits) - 1)) << unused
    return [(v >> (10 * (m - 1 - k))) & 1023 for k in range(m)]


def word_values(env):
    data = data_words(env)
    return data + words_check(data)


def words_of(env):
    """§3.2 writing: the envelope's words, data words then check words."""
    return [WORDS[v] for v in word_values(env)]


def name_word(s):
    """§3.2 reading, step 1: a word's value, or None when the position is unreadable."""
    if len(s) < 4 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" for ch in s):
        return None  # ASCII letters only: "?", a digit, U+212A KELVIN SIGN and the like make it unreadable
    low = s.lower()
    i = WORD_BY_PREFIX.get(low[:4])
    if i is None:
        return None
    w = WORDS[i]
    if len(low) > len(w) or not w.startswith(low):
        return None
    return i


_COLS = {}


def _columns(m):
    """col_k: what a value of 1 at position k adds to the remainder (the remainder is affine in the values)."""
    if m not in _COLS:
        zero = polymod_r(list(WORDS_CS) + [0] * m, WORDS_CHECK)
        cols = []
        for k in range(m):
            unit = [0] * m
            unit[k] = 1
            cols.append([a ^ b for a, b in zip(polymod_r(list(WORDS_CS) + unit, WORDS_CHECK), zero)])
        _COLS[m] = cols
    return _COLS[m]


def _solve(cols, target):
    """Solves sum x_j cols[j] = target over GF(1024); the x, or None if no solution."""
    u = len(cols)
    rows = [[cols[j][i] for j in range(u)] + [target[i]] for i in range(len(target))]
    piv_row = 0
    for j in range(u):
        p = next((i for i in range(piv_row, len(rows)) if rows[i][j]), None)
        assert p is not None, "the columns are not independent"
        rows[piv_row], rows[p] = rows[p], rows[piv_row]
        inv = ginv(rows[piv_row][j])
        rows[piv_row] = [gmul(inv, x) for x in rows[piv_row]]
        for i in range(len(rows)):
            if i != piv_row and rows[i][j]:
                f = rows[i][j]
                rows[i] = [a ^ gmul(f, b) for a, b in zip(rows[i], rows[piv_row])]
        piv_row += 1
    if any(rows[i][u] for i in range(u, len(rows))):
        return None
    return [rows[j][u] for j in range(u)]


def correct(values, unreadable, bound=WORDS_BOUND):
    """§3.2 reading, step 4: fills the unreadable positions (indices from 0) and changes
    e wrong words with 2e + f <= bound. Returns (values, wrong indices) or None."""
    m = len(values)
    f = len(unreadable)
    if f > bound:
        return None
    cols = _columns(m)
    got = [0 if k in unreadable else v for k, v in enumerate(values)]
    rem = polymod_r(list(WORDS_CS) + got, WORDS_CHECK)
    target = [a ^ b for a, b in zip(rem, [0] * (WORDS_CHECK - 1) + [1])]
    readable = [k for k in range(m) if k not in unreadable]
    for e in range((bound - f) // 2 + 1):
        for wrong in itertools.combinations(readable, e):
            pos = sorted(unreadable) + list(wrong)
            x = _solve([cols[k] for k in pos], target)
            if x is None or any(x[f + j] == 0 for j in range(e)):
                continue
            out = list(got)
            for k, d in zip(pos, x):
                out[k] ^= d
            assert words_valid(out)
            return out, sorted(wrong)
    return None


def envelope_of_words(values):
    """§3.2 reading, step 5: the envelope, or None and why the words are not AQRV words."""
    m = len(values) - WORDS_CHECK
    n = [k for k, (_, dm, _) in WORDS_TABLE.items() if dm == m][0]
    bits, _, unused = WORDS_TABLE[n]
    v = 0
    for x in values[:m]:
        v = (v << 10) | x
    if v & ((1 << unused) - 1):
        return None, "the last data word's %d unused bits are not 0" % unused
    v >>= unused
    env = ((0b11111 << bits) | v).to_bytes(n, "big")
    if env[0] & 7 > 4:
        return None, "step %d is not defined" % (env[0] & 7)
    return env, None


def read_words(given, passphrase, bound=WORDS_BOUND):
    """§3.2 reading, then §6's. The answer has the shape of a words case's expect."""
    if len(given) not in (36, 48, 56):
        return {"outcome": "not_aqrv_words", "why": "%d words" % len(given)}
    named = [name_word(s) for s in given]
    unreadable = [k for k, v in enumerate(named) if v is None]
    fixed = correct(named, unreadable, bound)
    if fixed is None:
        return {"outcome": "words_do_not_check"}
    values, wrong = fixed
    env, why = envelope_of_words(values)
    if env is None:  # after a correction, bad unused bits or a reserved step mean the correction is suspect
        return {"outcome": "words_do_not_check" if unreadable or wrong else "not_aqrv_words", "why": why}
    got = read(env, passphrase)
    if got["outcome"] != "opens":
        return {"outcome": got["outcome"]}
    changed = sorted(unreadable + wrong)
    return {"outcome": "opens", "unreadable": [k + 1 for k in unreadable], "wrong": [k + 1 for k in wrong],
            "corrected": [{"position": k + 1, "input": given[k], "word": WORDS[values[k]]} for k in changed],
            "words": [WORDS[v] for v in values], "envelope": hx(env), "kind": kh(got["kind"]),
            "item": got["item"]}


# ------------------------------------------------------------ words from text (§3.2, reading words from text)

TEXT_MAX_BYTES = 16 * 1024  # text longer than this, in UTF-8 bytes, is too many
TEXT_MAX_CUTS = 1024  # a run with more cuts than this is too many
TEXT_MAX_READINGS = 1024  # more readings than this is too many
TEXT_MAX_POSITIONS = 56  # a reading with more positions is dropped
MARK_RANGES = ((0x0300, 0x036F), (0x1AB0, 0x1AFF), (0x1DC0, 0x1DFF), (0x20D0, 0x20FF), (0xFE20, 0xFE2F))
TEXT_SIZES = (36, 48, 56)


def _mark(c):
    return any(a <= ord(c) <= b for a, b in MARK_RANGES)


def _letter(c):
    """Unicode's Alphabetic property, as far as the vectors need it: the letter categories and Nl.
    Alphabetic also holds some marks and symbols (Other_Alphabetic); _text_chars_ok keeps those out
    of the vectors' texts, so this test and the property agree on every character used."""
    return c.isalpha() or unicodedata.category(c) == "Nl"


def _text_chars_ok(text):
    for c in text:
        if ord(c) >= 0x80:
            assert unicodedata.category(c)[0] in "LNPZC" or _mark(c), "U+%04X" % ord(c)


class _TooMany(Exception):
    pass


def _join_wraps(t):
    """A hyphen after a letter, spaces or tabs, LF or CR LF, spaces or tabs, then a letter: the
    hyphen and everything up to that letter go."""
    out = []
    i, n = 0, len(t)
    while i < n:
        if t[i] == "-" and i > 0 and _letter(t[i - 1]):
            j = i + 1
            while j < n and t[j] in " \t":
                j += 1
            if t[j:j + 2] == "\r\n":
                j += 1
            if j < n and t[j] == "\n":
                j += 1
                while j < n and t[j] in " \t":
                    j += 1
                if j < n and _letter(t[j]):
                    i = j
                    continue
        out.append(t[i])
        i += 1
    return "".join(out)


def _in_run(c):
    return c == "?" or _letter(c) or _mark(c)


def _runs(t):
    """The runs in text order, each as (the last number in the separators just before it, or None; its text)."""
    out = []
    number = None
    i, n = 0, len(t)
    while i < n:
        j = i
        if t[i] == "?":
            while j < n and t[j] == "?":
                j += 1
        elif _in_run(t[i]):
            while j < n and _in_run(t[j]) and t[j] != "?":
                j += 1
        else:
            while j < n and not _in_run(t[j]):
                j += 1
            nums = re.findall("[0-9]+", t[i:j])
            number = int(nums[-1]) if nums else None
            i = j
            continue
        out.append((number, t[i:j]))
        number = None
        i = j
    return out


def _ordered(runs):
    nums = [k for k, _ in runs]
    if runs and None not in nums and sorted(nums) == list(range(1, len(runs) + 1)):
        return [r for _, r in sorted(runs)]
    return [r for _, r in runs]


def _cuts(run):
    """Every way to cut a run of ASCII letters into pieces of 4 to 8 letters that each name a word,
    a longer first piece first, then a longer second; raises _TooMany past TEXT_MAX_CUTS."""
    n = len(run)
    nxt = [[k for k in range(8, 3, -1) if i + k <= n and name_word(run[i:i + k]) is not None] for i in range(n)]
    ways = [0] * (n + 1)
    ways[n] = 1
    for i in range(n - 1, -1, -1):
        ways[i] = sum(ways[i + k] for k in nxt[i])
    if ways[0] > TEXT_MAX_CUTS:
        raise _TooMany
    out = []
    stack = [(0, [])]
    while stack:
        i, path = stack.pop()
        if i == n:
            out.append(path)
            continue
        for k in reversed([k for k in nxt[i] if ways[i + k]]):  # pushed shortest first, so the longest comes off first
            stack.append((i + k, path + [run[i:i + k]]))
    assert len(out) == ways[0]
    return out


def _readings(choices):
    """Every reading of at most TEXT_MAX_POSITIONS positions, in order; raises _TooMany past TEXT_MAX_READINGS."""
    fewest = [0] * (len(choices) + 1)
    for r in range(len(choices) - 1, -1, -1):
        fewest[r] = fewest[r + 1] + min(len(c) for c in choices[r])
    out = []
    stack = [(0, [])]
    while stack:
        r, path = stack.pop()
        if r == len(choices):
            if len(out) == TEXT_MAX_READINGS:
                raise _TooMany
            out.append(path)
            continue
        for cut in reversed(choices[r]):
            if len(path) + len(cut) + fewest[r + 1] <= TEXT_MAX_POSITIONS:
                stack.append((r + 1, path + cut))
    return out


def decode_words(given):
    """§3.2 reading, steps 2 to 5, without §6: ("envelope", env, values, unreadable, wrong),
    or ("not_aqrv_words", why) or ("words_do_not_check", why)."""
    if len(given) not in TEXT_SIZES:
        return ("not_aqrv_words", "%d positions" % len(given))
    named = [name_word(s) for s in given]
    unreadable = [k for k, v in enumerate(named) if v is None]
    fixed = correct(named, unreadable)
    if fixed is None:
        return ("words_do_not_check", "no correction with 2e + f <= 4")
    values, wrong = fixed
    env, why = envelope_of_words(values)
    if env is None:
        return ("words_do_not_check" if unreadable or wrong else "not_aqrv_words", why)
    return ("envelope", env, values, unreadable, wrong)


def text_readings(text):
    """The text's runs' cuts and its readings, each a list of positions as given; raises _TooMany."""
    if len(text.encode("utf-8")) > TEXT_MAX_BYTES:
        raise _TooMany
    choices = []
    for run in _ordered(_runs(_join_wraps(text))):
        cuts = _cuts(run) if run.isascii() and run.isalpha() else []
        choices.append(cuts or [[run]])
    return choices, _readings(choices)


def read_words_text(text, passphrase):
    """§3.2, reading words from text, then §6. The answer has the shape of a words_text entry's expect."""
    try:
        choices, readings = text_readings(text)
    except _TooMany:
        return {"outcome": "too_many"}
    counted = [r for r in readings if len(r) in TEXT_SIZES]
    if not counted:
        first = readings[0] if readings else [p for c in choices for p in c[0]]
        return {"outcome": "not_aqrv_words", "reason": "%d positions" % len(first)}
    named = [[name_word(p) for p in r] for r in counted]
    exact = [r for r, v in zip(counted, named) if None not in v and words_valid(v)]
    found, refused = [], []
    for r in exact or counted:
        got = decode_words(r)
        if got[0] == "envelope":
            found.append((len(got[3]) + len(got[4]), r, got))
        elif got[0] == "not_aqrv_words":
            refused.append(got[1])
    if found and (refused or len({g[1] for _, _, g in found}) > 1):
        return {"outcome": "ambiguous"}
    if not found:
        return {"outcome": "not_aqrv_words", "reason": refused[-1]} if refused else {"outcome": "words_do_not_check"}
    _, given, (_, env, values, unreadable, wrong) = min(found, key=lambda x: x[0])
    got = read(env, passphrase)
    if got["outcome"] != "opens":
        return {"outcome": got["outcome"]}
    changed = sorted(unreadable + wrong)
    return {"outcome": "opens", "unreadable": [k + 1 for k in unreadable], "wrong": [k + 1 for k in wrong],
            "corrected": [{"position": k + 1, "input": given[k], "word": WORDS[values[k]]} for k in changed],
            "words": [WORDS[v] for v in values], "envelope": hx(env), "kind": kh(got["kind"]),
            "item": got["item"]}


# ------------------------------------------------------------ case building


def _bip39_published():
    """BIP 39's published entropies and words (the Trezor reference vectors, english)."""
    path = os.path.join(ROOT, "reference", "bip39-vectors", "vectors.json")
    return {bytes.fromhex(h): w for h, w, *_ in json.load(open(path))["english"]}


_BIP39 = _bip39_published()
_MNEMONIC = Mnemonic("english")


def bip39(byte, ln):
    """A BIP 39 entropy of ln bytes, all `byte`, with its words. Where the published
    vectors list it, the words are theirs; at the lengths they do not list (20 and 28
    bytes) python-mnemonic's, which the published ones agree with at the others."""
    ent = bytes([byte]) * ln
    words = _MNEMONIC.to_mnemonic(ent)
    if ent in _BIP39:
        assert _BIP39[ent] == words, (byte, ln)
    else:
        assert ln in (20, 28), (byte, ln)
    return ent


def words_extra(ent):
    """What an entropy case records beside its item: the BIP 39 words of the entropy."""
    return {"bip39_words": _MNEMONIC.to_mnemonic(ent)}


# The byte each length's kind case takes (the 24-word one is the step 0 case).
KIND_BYTE = {0x10: 0x7F, 0x14: 0x00, 0x18: 0x80, 0x1C: 0xFF}


def shake(label, n):
    return hashlib.shake_256(b"AQRV vector " + label.encode()).digest(n)


def salt_of(name, n=53):
    return hashlib.sha256(b"AQRV vector salt " + name.encode()).digest()[:SALT_LEN[n]]


def kh(k):
    return "0x%02X" % k


def make_p(name, item, r, unused_mask=0):
    """P = item bytes (unused low bits of the last byte filled), then padding."""
    stream = shake("padding " + name, r + 1)
    fill = stream[0] & unused_mask
    body = bytearray(item)
    if unused_mask:
        assert body[-1] & unused_mask == 0
        body[-1] |= fill
    padding = stream[1:1 + r - len(item)]
    return bytes(body) + padding, fill, padding


def seal(name, group, n, step, passphrase, kind, p, item_hex, expect_item, extra=None, salt=None):
    r, t = SIZES[n]
    assert len(p) == r
    salt = salt or salt_of(name, n)
    assert len(salt) == SALT_LEN[n]
    header = 0xF8 | step
    d = derive(passphrase, salt, step)
    c = xor(p, d["keystream"][:r])
    tags = {kh(k): hx(tag(d["k_mac"], header, n, salt, k, c, t)) for k in KINDS_AT[n]}
    assert len(set(tags.values())) == len(tags), "two kinds share a tag: choose another salt"
    env = bytes([header]) + salt + c + bytes.fromhex(tags[kh(kind)])
    assert len(env) == n
    case = {
        "name": name,
        "group": group,
        "size": n,
        "step": step,
        "memory_kib": STEPS[step],
        "passphrase": passphrase,
        "kind": kh(kind),
        "kind_name": KIND_NAME[kind],
        "item_bytes": item_hex,
        "salt": hx(salt),
        "header": "0x%02X" % header,
        "values": {
            "pw": hx(d["pw"]),
            "PRK": hx(d["prk"]),
            "K_enc": hx(d["k_enc"]),
            "K_mac": hx(d["k_mac"]),
            "keystream": hx(d["keystream"][:r]),
            "P": hx(p),
            "C": hx(c),
            "hmac_message": hx(tag_message(header, n, salt, kind, c)),
            "tags": tags,
            "tag": tags[kh(kind)],
        },
        "envelope": hx(env),
    }
    if extra:
        case.update(extra)
    return case, env


def valid_case(name, group, n, step, passphrase, kind, item, unused_mask=0, expect_item=None,
               extra=None, salt=None, pad_name=None):
    r, _ = SIZES[n]
    p, fill, padding = make_p(pad_name or name, item, r, unused_mask)
    extra = dict(extra or {})
    extra["padding"] = hx(padding)
    if unused_mask:
        extra["last_byte_fill"] = "0x%02X" % fill
    case, env = seal(name, group, n, step, passphrase, kind, p, hx(item), expect_item, extra, salt)
    got = read(env, passphrase)
    assert got["outcome"] == "opens" and got["kind"] == kind, (name, got)
    assert got["item"] == expect_item, (name, got["item"], expect_item)
    case["expect"] = {"outcome": "opens", "kind": kh(kind), "item": expect_item}
    return case, env


def fail_case(name, group, env, passphrase, outcome, why, source=None, note=""):
    got = read(env, passphrase)
    assert got["outcome"] == outcome, (name, got)
    if outcome == "does_not_open":
        assert got["why"] == "no_tag_matches", (name, got)
    expect = {"outcome": outcome}
    if outcome == "does_not_open":
        expect["why"] = "no kind's tag matches"
    expect["reason"] = why
    case = {"name": name, "group": group, "size": len(env), "passphrase": passphrase,
            "envelope": hx(env), "expect": expect}
    if source:
        case["made_from"] = source
    if note:
        case["note"] = note
    return case


def crafted_case(name, kind, n, p, passphrase, detail, step=0):
    """A right tag over a P the format refuses: made with the key."""
    case, env = seal(name, "fail-right-tag", n, step, passphrase, kind, p, hx(p), None)
    got = read(env, passphrase)
    assert got["outcome"] == "does_not_open" and got["why"] == "format" and got["kind"] == kind, (name, got)
    case["expect"] = {"outcome": "does_not_open", "why": "the tag of kind %s matches and the item fails its layout" % kh(kind),
                      "reason": detail}
    return case


# ------------------------------------------------------------ codex32 input


def codex_item(s):
    """Item bytes, unused-bit mask and the five fields of a codex32 string."""
    upper = s.isupper()
    assert s.islower() or upper
    s = s.lower()
    assert s.startswith("ms1")
    body = s[3:-13]
    c = len(body) - 6
    size = [k for k, v in CODEX_C.items() if v == c][0]
    vals = [CHARSET.index(ch) for ch in body]
    threshold, ident, index, payload = vals[0], vals[1:5], vals[5], vals[6:]
    bits = (size << 1) | int(upper)
    for v in [threshold] + ident + [index] + payload:
        bits = (bits << 5) | v
    nbits = 4 + 5 * (1 + 4 + 1 + c)
    nbytes = (nbits + 7) // 8
    pad = nbytes * 8 - nbits
    return (bits << pad).to_bytes(nbytes, "big"), (1 << pad) - 1, size, nbytes


def codex_p(head_size, upper, threshold, ident, index, payload):
    bits = (head_size << 1) | upper
    for v in [threshold] + ident + [index] + payload:
        bits = (bits << 5) | v
    return bits


# -------------------------------------------------------------------- QR


QR_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"  # QR alphanumeric mode, in its index order
TEXT_LEN = 47
B43 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:"  # Electrum's base43, as KEF's Krux writes it


def text_of(env):
    """§3: the 32-byte size in a QR code, 47 base-45 digits, most significant first."""
    assert len(env) == 32
    v = int.from_bytes(env, "big")
    s = ""
    for _ in range(TEXT_LEN):
        v, d = divmod(v, 45)
        s = QR_ALNUM[d] + s
    assert v == 0
    return s


def envelope_of_text(s):
    """§9: the 32 bytes a scanned text stands for, or None and why it is not recognised."""
    if len(s) != TEXT_LEN:
        return None, "%d characters, not 47" % len(s)
    for i, ch in enumerate(s):
        if ch not in QR_ALNUM:
            return None, "character %d (from 1), %r, is not in QR's alphanumeric alphabet" % (i + 1, ch)
    v = 0
    for ch in s:
        v = v * 45 + QR_ALNUM.index(ch)
    if v >= 256 ** 32:
        return None, "its value is 256^32 or more, so it is not 32 bytes"
    return v.to_bytes(32, "big"), None


def read_text(s, passphrase):
    """§9 for a 47-character code: decoded, then the usual reading."""
    env, why = envelope_of_text(s)
    if env is None:
        return {"outcome": "not_recognised", "why": why}
    return read(env, passphrase)


def base43_of(b):  # Electrum's base_encode for base 43: big-endian, a leading zero byte is a 0
    v = int.from_bytes(b, "big")
    s = ""
    while v:
        v, d = divmod(v, 43)
        s = B43[d] + s
    return "0" * (len(b) - len(b.lstrip(b"\x00"))) + s


def qr_of(env):
    n = len(env)
    version, ecc = {32: (2, QrCode.Ecc.LOW), 53: (3, QrCode.Ecc.LOW), 62: (4, QrCode.Ecc.MEDIUM)}[n]
    seg = QrSegment.make_alphanumeric(text_of(env)) if n == 32 else QrSegment.make_bytes(env)
    qr = QrCode.encode_segments([seg], ecc, version, version, -1, False)
    return qr


def png_of(qr, scale=8, quiet=4):
    """A 1-bit greyscale PNG with the three required chunks and nothing else."""
    size = qr.get_size()
    side = (size + 2 * quiet) * scale
    rows = bytearray()
    for y in range(side):
        my = y // scale - quiet
        row = bytearray((side + 7) // 8)
        for x in range(side):
            mx = x // scale - quiet
            dark = 0 <= mx < size and 0 <= my < size and qr.get_module(mx, my)
            if not dark:
                row[x // 8] |= 0x80 >> (x % 8)
        rows += b"\x00" + row

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", side, side, 1, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + chunk(b"IEND", b""))


# ------------------------------------------------------------------ cases

PASS = "aqrv vector passphrase"
UNI = "café ✨ Ångström"
UNI_NFD = unicodedata.normalize("NFD", UNI)
assert UNI != UNI_NFD and nfc(UNI_NFD) == UNI


def build_37():
    """The 37-byte size (§3.2), which exists only as words: the 32-byte size's cases with a 16-byte salt."""
    out = []
    n = 37
    r, t = SIZES[n]
    for step in (0, 4):
        nm = "step-%d-12w-%d" % (step, n)
        ent = bip39(0x00, 16)  # "abandon ... about"
        case, env = valid_case(nm, "step", n, step, PASS, 0x10, ent,
                               expect_item={"type": "entropy", "hex": hx(ent)}, extra=words_extra(ent))
        out.append(case)
        if step == 0:
            base = (env, PASS, nm)
    for kind, label, tname in ((0x40, "passphrase", "passphrase"), (0x41, "note", "note")):
        for how, text in (
            ("shortest", "x"),
            ("longest", "0123456789abcdefghijklmnopqrstuvwxyz"[:r - 1]),
            ("non-ascii", "Zoë ✓ 日本"),
        ):
            b = text.encode("utf-8")
            assert 1 <= len(b) <= r - 1
            nm = "%s-%s-%d" % (label, how, n)
            out.append(valid_case(nm, "kind", n, 0, PASS, kind, bytes([len(b)]) + b,
                                  expect_item={"type": tname, "text": text}, extra={"text_bytes": len(b)})[0])
    for label, byte in (("zero", 0x00), ("ones", 0xFF)):
        ent = bip39(byte, 16)
        nm = "%s-seed-12w-%d" % (label, n)
        out.append(valid_case(nm, "seed", n, 0, PASS, 0x10, ent, expect_item={"type": "entropy", "hex": hx(ent)},
                              extra=words_extra(ent))[0])
    ent = bip39(0x80, 16)
    salt = salt_of("unicode-%d" % n, n)
    envs = []
    for form, pp in (("nfc", UNI), ("nfd", UNI_NFD)):
        nm = "unicode-%s-%d" % (form, n)
        case, env = valid_case(nm, "unicode", n, 0, pp, 0x10, ent,
                               expect_item={"type": "entropy", "hex": hx(ent)}, salt=salt,
                               pad_name="unicode-%d" % n,
                               extra=dict(words_extra(ent), passphrase_utf8=hx(pp.encode())))
        out.append(case)
        envs.append(env)
    assert envs[0] == envs[1]
    env, pp, src = base
    out.append(fail_case("fail-wrong-passphrase-%d" % n, "fail", env, PASS + "!", "does_not_open",
                         "a wrong passphrase", src))
    for kind in (0x20, 0x30, 0x50):
        nm = "fail-kind-%02X-not-at-%d" % (kind, n)
        salt = salt_of(nm, n)
        d = derive(PASS, salt, 0)
        p = shake("padding " + nm, r)
        c = xor(p, d["keystream"][:r])
        envk = bytes([0xF8]) + salt + c + tag(d["k_mac"], 0xF8, n, salt, kind, c, t)
        assert all(tag(d["k_mac"], 0xF8, n, salt, k, c, t) != envk[-t:] for k in KINDS_AT[n])
        out.append(fail_case(nm, "fail", envk, PASS, "does_not_open",
                             "the tag is right for kind %s (%s), which the 37-byte size does not hold, so a reader does not test it" % (kh(kind), KIND_NAME[kind]),
                             note="made with the key: P is %s, and the tag is HMAC over H || N || salt || %s || C" % (hx(p), kh(kind))))
    assert len(out) == 16
    return out, base


def _pick(label, count, m, avoid=()):
    """count distinct positions (indices from 0) of m, drawn from shake with a retry counter."""
    tries = 0
    while True:
        s = shake("words positions %s %d" % (label, tries), 2 * count)
        pos = [((s[2 * k] << 8) | s[2 * k + 1]) % m for k in range(count)]
        if len(set(pos)) == count and not set(pos) & set(avoid):
            return pos
        tries += 1


def decodes_without_rule(given):
    """Whether a decoder allowed 2e + f <= 6 finds valid words."""
    named = [name_word(x) for x in given]
    return correct(named, [k for k, v in enumerate(named) if v is None], bound=6) is not None


def _wrong_value(label, orig):
    s = shake("words wrong %s" % label, 2)
    return (orig + 1 + ((s[0] << 8) | s[1]) % 1023) % 1024


def build_words(bases):
    """§3.2: the words cases. bases maps a size to (envelope, passphrase, case name, case expect)."""
    out = []
    for n in (37, 53, 62):
        env, pp, src, exp = bases[n]
        vals = word_values(env)
        full = [WORDS[v] for v in vals]
        m = len(vals)
        k = m - WORDS_CHECK

        def opens(name, group, given, unreadable, wrong, note):
            changed = sorted(unreadable + wrong)
            return {"name": name, "group": group, "size": n, "source": src, "passphrase": pp, "input": given,
                    "note": note,
                    "expect": {"outcome": "opens", "unreadable": [i + 1 for i in sorted(unreadable)],
                               "wrong": [i + 1 for i in sorted(wrong)],
                               "corrected": [{"position": i + 1, "input": given[i], "word": full[i]} for i in changed],
                               "words": full, "envelope": hx(env), "kind": exp["kind"], "item": exp["item"]}}

        def damaged(label, f, e, first=None):
            if first is None:
                pos = _pick("%s" % label, f + e, m)
                unr, wr = pos[:f], pos[f:]
            else:
                unr, wr = first
            given = list(full)
            for i in unr:
                given[i] = "?"
            for i in wr:
                given[i] = WORDS[_wrong_value("%s %d" % (label, i), vals[i])]
            return given, unr, wr

        # Corrections the rule allows.
        for f, e in ((0, 1), (0, 2), (1, 0), (1, 1), (2, 0), (2, 1), (3, 0), (4, 0)):
            nm = "words-correct-%du-%dw-%d" % (f, e, m)
            given, unr, wr = damaged(nm, f, e, ([0], [m - 1]) if (f, e) == (1, 1) else None)
            out.append(opens(nm, "words-correct", given, unr, wr,
                             "%d unreadable and %d wrong: 2e + f = %d" % (f, e, 2 * e + f)))
        # Must not check.
        for f, e, why in ((1, 2, "one unreadable and two wrong words: 2e + f = 5"),
                          (5, 0, "five unreadable words: 2e + f = 5"),
                          (0, 3, "three wrong words: 2e + f = 6"),
                          (7, 0, "seven unreadable words: more than the six check words")):
            nm = "words-no-check-%du-%dw-%d" % (f, e, m)
            given, unr, wr = damaged(nm, f, e)
            out.append({"name": nm, "group": "words-do-not-check", "size": n, "source": src, "passphrase": pp,
                        "input": given,
                        "expect": {"outcome": "words_do_not_check", "reason": why,
                                   "decodes_without_the_rule": decodes_without_rule(given)}})

        # Not AQRV words: other bits with a check made over them.
        def recheck(data):
            return [WORDS[v] for v in data + words_check(data)]

        data = vals[:k]
        bits, _, unused = WORDS_TABLE[n]
        if n in (37, 53):
            d2 = list(data)
            d2[-1] |= 1
            d_unused = d2
            out.append({"name": "words-unused-bit-%d" % m, "group": "words-not-aqrv", "size": n, "source": src,
                        "passphrase": pp, "input": recheck(d2),
                        "expect": {"outcome": "not_aqrv_words",
                                   "reason": "the lowest of the last data word's %d unused bits is 1, with check words made over it" % unused}})
        if n == 53:
            d2 = list(data)
            d2[0] = (5 << 7) | (d2[0] & 0x7F)
            out.append({"name": "words-step-5-%d" % m, "group": "words-not-aqrv", "size": n, "source": src,
                        "passphrase": pp, "input": recheck(d2),
                        "expect": {"outcome": "not_aqrv_words",
                                   "reason": "the step is 5, which is not defined, with check words made over it: the envelope would begin 0xFD"}})
            # The same two bad lists with one other word changed: the correction restores the bad list.
            for nm, bad, what in (("words-corrected-step-5-%d" % m, d2, "step 5"),
                                  ("words-corrected-unused-bit-%d" % m, d_unused, "a set unused bit")):
                g = recheck(bad)
                i = 9
                assert 0 < i < k - 1
                g[i] = WORDS[_wrong_value(nm, WORDS.index(g[i]))]
                out.append({"name": nm, "group": "words-do-not-check", "size": n, "source": src, "passphrase": pp,
                            "input": g,
                            "expect": {"outcome": "words_do_not_check",
                                       "reason": "the words of %s with position %d changed: the correction restores that list, and %s after a correction means the words do not check" % (
                                           "words-step-5-%d" % m if what == "step 5" else "words-unused-bit-%d" % m, i + 1, what),
                                       "decodes_without_the_rule": decodes_without_rule(g)}})
        if n == 37:
            out.append({"name": "words-35", "group": "words-not-aqrv", "source": src, "passphrase": pp,
                        "input": full[:-1],
                        "expect": {"outcome": "not_aqrv_words", "reason": "35 words: 36 with the last removed"}})
            out.append({"name": "words-37", "group": "words-not-aqrv", "source": src, "passphrase": pp,
                        "input": full + [full[-1]],
                        "expect": {"outcome": "not_aqrv_words", "reason": "37 words: 36 with the last repeated"}})
        if n == 53:
            out.append({"name": "words-49", "group": "words-not-aqrv", "source": src, "passphrase": pp,
                        "input": full + [full[-1]],
                        "expect": {"outcome": "not_aqrv_words", "reason": "49 words: 48 with the last repeated"}})

        # Naming.
        if n == 37:
            out.append(opens("words-first-four-%d" % m, "words-naming", [w[:4] for w in full], [], [],
                             "every word by its first four letters"))
            i = next(i for i, w in enumerate(full) if len(w) >= 5)
            g = list(full)
            ch = g[i][4]
            g[i] = g[i][:4] + chr((ord(ch) - 97 + 1) % 26 + 97) + g[i][5:]
            out.append(opens("words-wrong-fifth-letter-%d" % m, "words-naming", g, [i], [],
                             "position %d's fifth letter is wrong: it matches no word in full, so it is unreadable and filled" % (i + 1)))
            i = next(i for i, w in enumerate(full) if "k" in w)
            g = list(full)
            g[i] = g[i].replace("k", "\u212a")
            assert g[i].lower() != g[i] and g[i].lower().replace("\u212a".lower(), "k") == full[i]
            out.append(opens("words-kelvin-sign-%d" % m, "words-naming", g, [i], [],
                             "position %d is %s with U+212A KELVIN SIGN in place of k: not an ASCII letter, so it is unreadable and filled" % (i + 1, full[i])))
        if n == 53:
            g = []
            for i, w in enumerate(full):
                ln = 4 + i % (len(w) - 3)
                g.append(w[:ln].upper())
            out.append(opens("words-upper-case-%d" % m, "words-naming", g, [], [],
                             "every word in upper case, from its first four letters to all of them"))
            i = len(full) // 2
            g = list(full)
            g[i] = g[i] + "s"
            out.append(opens("words-letter-added-%d" % m, "words-naming", g, [i], [],
                             "position %d has a letter added: longer than the word, so it is unreadable and filled" % (i + 1)))
        if n == 62:
            out.append(opens("words-in-full-%d" % m, "words-naming", list(full), [], [], "every word in full"))
            nope = next(a + b + c + d for a in "zyx" for b in "zyx" for c in "zyx" for d in "zyx"
                        if a + b + c + d not in WORD_BY_PREFIX)
            i = 2
            g = list(full)
            g[i] = nope
            out.append(opens("words-no-such-word-%d" % m, "words-naming", g, [i], [],
                             "position %d is %r, four letters that begin no word, so it is unreadable and filled" % (i + 1, nope)))
    # Every case is read back by read_words and must agree.
    for wc in out:
        got = read_words(wc["input"], wc["passphrase"])
        want = dict(wc["expect"])
        if want["outcome"] != "opens":
            assert got["outcome"] == want["outcome"], (wc["name"], got)
            if want["outcome"] == "words_do_not_check":
                assert read_words(wc["input"], wc["passphrase"], bound=4)["outcome"] == "words_do_not_check"
        else:
            assert got == want, (wc["name"], got, want)
    return out


def _cut_pool():
    """Runs of two list words, the first by 4 letters or more and the second by 4 or more, that cut
    exactly two ways, each into two pieces naming words: the same first word u, and v or another
    word z second. Keyed by v XOR z, the change the second reading makes at v's position; the
    shortest run first."""
    at = {}  # a substring of a word, from its fifth letter on -> (word, where it starts)
    for ui, u in enumerate(WORDS):
        for s in range(4, len(u)):
            for j in range(1, 5):
                if s + j <= len(u):
                    at.setdefault(u[s:s + j], []).append((ui, s))
    found = []
    for vi, v in enumerate(WORDS):  # u's piece takes v's first j letters as well: u[:l + j] then v[j:k]
        for j in range(1, len(v) - 3):
            for k in range(j + 4, len(v) + 1):
                zi = name_word(v[j:k])
                if zi is not None and zi != vi:
                    for ui, l in at.get(v[:j], []):
                        found.append((WORDS[ui][:l] + v[:k], ui, l, vi, k, zi))
    for zi, z in enumerate(WORDS):  # u's piece gives its last d letters to z: u[:l - d] then u[l - d:l] + v[:k]
        for d in range(1, min(4, len(z) - 4) + 1):
            vi = name_word(z[d:d + 4])
            if vi is None or vi == zi:
                continue
            for k in range(4, min(len(z) - d, len(WORDS[vi])) + 1):
                if WORDS[vi][:k] == z[d:d + k]:
                    for ui, s in at.get(z[:d], []):
                        found.append((WORDS[ui][:s + d] + WORDS[vi][:k], ui, s + d, vi, k, zi))
    pool = {}
    for run, ui, l, vi, k, zi in sorted(set(found), key=lambda f: (len(f[0]), f)):
        if (vi ^ zi) in pool:
            continue
        cuts = _cuts(run)
        if len(cuts) == 2 and [WORDS[ui][:l], WORDS[vi][:k]] in cuts and all(len(c) == 2 for c in cuts):
            pool[vi ^ zi] = (run, ui, vi, zi)
    return pool


def _ambiguous(vals):
    """A text with two readings that give two envelopes: three runs that each cut two ways, and four
    positions unreadable in both. The first reading is the given words with three pairs changed; the
    second differs from it at the three second words of those pairs and at the four unreadable ones,
    a codeword of weight 7 apart, so each reading fills its four positions to an envelope of its own.
    Returns (text, first words, second words, the unreadable positions)."""
    m = len(vals)
    k = m - WORDS_CHECK
    pool = _cut_pool()
    pairs = ((9, 10), (19, 20), (29, 30))  # (u, v) positions, away from the step's data word and the last
    D = [b for _, b in pairs]
    cols = _columns(m)
    free = [p for p in range(1, m) if p != k - 1 and all(p not in pr for pr in pairs)]
    for P in itertools.combinations(free, 4):
        others = D[1:] + list(P)
        x = _solve([cols[j] for j in others], cols[D[0]])  # c: 1 at D[0], x elsewhere, a codeword's difference
        c = dict(zip(others, x))
        c[D[0]] = 1
        for s in sorted(pool):
            ds = [gmul(s, c[b]) for b in D]
            if not all(dl in pool for dl in ds):
                continue
            data = list(vals[:k])
            runs = {}
            for (a, b), dl in zip(pairs, ds):
                run, ui, vi, zi = pool[dl]
                data[a], data[b] = ui, vi
                runs[a] = run
            first = data + words_check(data)
            second = list(first)
            for p, cp in c.items():
                second[p] ^= gmul(s, cp)
            assert words_valid(first) and words_valid(second) and first != second
            assert envelope_of_words(first)[0] and envelope_of_words(second)[0]
            tokens, p = [], 0
            while p < m:
                if p in runs:
                    tokens.append(runs[p])
                    p += 2
                    continue
                tokens.append("?" if p in P else WORDS[first[p]])
                p += 1
            return " ".join(tokens), first, second, list(P)
    raise AssertionError("no ambiguous text found")


FULL_WIDTH_DIGITS = str.maketrans("0123456789", "０１２３４５６７８９")


def build_words_text(bases):
    """§3.2, reading words from text: the words_text entries. bases maps a size to
    (envelope, passphrase, case name, case expect)."""
    out = []
    full_of = {}
    for n in (37, 53, 62):
        env, pp, src, exp = bases[n]
        full_of[len(word_values(env))] = ([WORDS[v] for v in word_values(env)], env, pp, src, exp)

    def opens(name, m, text, given=None, unreadable=()):
        full, env, pp, src, exp = full_of[m]
        given = given or full
        assert len(given) == m
        unr = sorted(unreadable)
        out.append({"name": "text-%s-%d" % (name, m), "group": "words-text", "source": src, "passphrase": pp,
                    "text": text,
                    "expect": {"outcome": "opens", "unreadable": [i + 1 for i in unr], "wrong": [],
                               "corrected": [{"position": i + 1, "input": given[i], "word": full[i]} for i in unr],
                               "words": full, "envelope": hx(env), "kind": exp["kind"], "item": exp["item"]}})

    def refused(name, m, text, outcome, reason, src=None):
        full, env, pp, src0, exp = full_of[m]
        out.append({"name": "text-%s-%d" % (name, m), "group": "words-text", "source": src or src0,
                    "passphrase": pp, "text": text, "expect": {"outcome": outcome, "reason": reason}})

    def numbered(fmt, words, sep="\n"):
        return sep.join(fmt % (i + 1, w) for i, w in enumerate(words)) + sep

    W = {m: full_of[m][0] for m in full_of}
    f4 = {m: [w[:4] for w in W[m]] for m in W}

    # Separators.
    for m in (36, 48, 56):
        opens("spaces", m, " ".join(W[m]))
        opens("lines", m, "\n".join(W[m]) + "\n")
    opens("crlf", 48, "\r\n".join(W[48]) + "\r\n")
    opens("tabs", 36, "\t".join(W[36]))
    opens("commas", 36, ", ".join(W[36]))
    opens("json-list", 48, json.dumps(f4[48]), f4[48])
    opens("bullets", 56, "".join("• %s\n" % w for w in W[56]))
    opens("nbsp", 36, " ".join(W[36]))
    opens("zero-width-space", 48, "​".join(W[48]))
    opens("bom", 56, "".join("﻿" + w for w in W[56]))
    opens("dashes", 36, "".join(w + ("–" if i % 2 else "—") for i, w in enumerate(W[36])))
    opens("curly-quotes", 48, " ".join(("“%s”" if i % 2 else "‘%s’") % w for i, w in enumerate(W[48])))
    opens("full-width", 56, "　".join(("%d．%s，" % (i + 1, w)).translate(FULL_WIDTH_DIGITS)
                                         for i, w in enumerate(W[56])))
    # Numbered: the numbers are 1 to n in text order, so the order stays.
    for (nm, fmt), m in zip((("number-space", "%d %s"), ("number-dot", "%d. %s"), ("number-paren", "%d) %s"),
                             ("number-parens", "(%d) %s"), ("number-colon", "%d: %s"), ("number-hash", "#%d %s"),
                             ("number-zeros", "%02d %s")), (36, 48, 56, 36, 48, 56, 36)):
        opens(nm, m, numbered(fmt, W[m]))
    opens("number-glued", 48, numbered("%d.%s", f4[48], sep=""), f4[48])
    opens("rows-of-four", 56, "".join("%d %s%s" % (i + 1, w, "\n" if i % 4 == 3 else "  ") for i, w in enumerate(W[56])))
    # First letters, run together, case.
    opens("first-four-spaced", 48, " ".join(f4[48]), f4[48])
    opens("first-four-run-together", 56, "".join(f4[56]), f4[56])
    opens("run-together", 36, "".join(W[36]))
    opens("run-together", 48, "".join(W[48]))
    mixed = []
    for i, w in enumerate(W[56]):
        piece = w[:4 + i % (len(w) - 3)]
        mixed.append((piece.upper(), piece.title(), piece)[i % 3])
    opens("mixed-run-together", 56, "".join(mixed), mixed)
    # A grid copied column by column.
    for m in (36, 48):
        rows = m // 4
        order = [r * 4 + col for col in range(4) for r in range(rows)]
        opens("columns", m, "".join("%d. %s\n" % (i + 1, W[m][i]) for i in order))
    rows = 12
    order = [r * 4 + col for col in range(4) for r in range(rows)]
    refused("columns-numbered-from-0", 48, "".join("%d. %s\n" % (i, W[48][i]) for i in order),
            "words_do_not_check", "a grid copied column by column, numbered 0 to 47: not 1 to 48, so the numbers only separate and the words stay in column order")
    opens("numbered-from-2", 36, "".join("%d %s\n" % (i + 2, w) for i, w in enumerate(W[36])))
    # Hyphens at a line break.
    j = next(i for i, w in enumerate(W[56]) if len(w) >= 6 and i > 4)
    w = W[56][j]
    opens("hyphen-break", 56, " ".join(W[56][:j]) + " " + w[:3] + "-\n" + w[3:] + " " + " ".join(W[56][j + 1:]))
    j = next(i for i, w in enumerate(W[36]) if len(w) >= 7 and i > 10)
    w = W[36][j]
    opens("hyphen-crlf", 36, "\n".join(W[36][:j]) + "\n" + w[:4] + "- \r\n\t" + w[4:] + "\n" + "\n".join(W[36][j + 1:]))
    # Unreadable positions.
    g = list(W[48])
    g[5], g[20] = "?", "??"
    opens("question-marks", 48, " ".join(g), g, [5, 20])
    i = 12
    g = list(f4[36])
    g[i + 1] = "?"
    opens("question-mark-between", 36, " ".join(f4[36][:i]) + " " + g[i] + "?" + g[i + 2] + " " + " ".join(f4[36][i + 3:]),
          g, [i + 1])
    i = next(i for i, w in enumerate(W[56]) if "e" in w)
    g = list(W[56])
    g[i] = g[i].replace("e", "é", 1)
    opens("combining-accent", 56, " ".join(g), g, [i])
    i = next(i for i, w in enumerate(W[48]) if "k" in w)
    g = list(W[48])
    g[i] = g[i].replace("k", "K")
    opens("kelvin-sign", 48, " ".join(g), g, [i])
    i = next(i for i, w in enumerate(W[36]) if len(w) == 8)
    g = list(W[36])
    g[i] = g[i] + "s"
    opens("nine-letters", 36, " ".join(g), g, [i])
    # A heading pasted with the words: two more positions, so not AQRV words.
    refused("heading", 48, "AQRV words:\n" + numbered("%d. %s", W[48]), "not_aqrv_words",
            "50 positions: the heading's AQRV and words are two positions, unreadable, before the 48 words")
    # Ambiguous: two readings, two envelopes.
    text, first, second, unr = _ambiguous(word_values(full_of[48][1]))
    refused("ambiguous", 48, text, "ambiguous",
            "three runs each cut two ways and positions %s are unreadable: the reading with %s, %s and %s fills to one envelope "
            "and the reading with %s, %s and %s to another" % (
                ", ".join(str(p + 1) for p in unr), *(WORDS[first[b]] for b in (10, 20, 30)),
                *(WORDS[second[b]] for b in (10, 20, 30))),
            src="crafted from %s" % full_of[48][3])
    # Too many.
    refused("advocate-56", 56, "advocate" * 56, "too_many", "advocate 56 times with no separators: more than 1024 cuts")
    t = " ".join(W[48])
    opens("16384-bytes", 48, t + " " * (TEXT_MAX_BYTES - len(t.encode())))
    refused("16385-bytes", 48, t + " " * (TEXT_MAX_BYTES + 1 - len(t.encode())), "too_many",
            "the words and spaces to 16385 bytes, one over the limit")

    for e in out:
        _text_chars_ok(e["text"])
        got = read_words_text(e["text"], e["passphrase"])
        want = e["expect"]
        if want["outcome"] == "opens":
            assert got == want, (e["name"], got, want)
        else:
            assert got["outcome"] == want["outcome"], (e["name"], got)
    names = [e["name"] for e in out]
    assert len(set(names)) == len(names)
    return out


def build():
    cases = []

    def add(pair):
        cases.append(pair[0])
        return pair[1]

    # Steps: a 24-word seed at every step, both sizes.
    base = {}
    for n in (53, 62):
        for step in range(5):
            nm = "step-%d-24w-%d" % (step, n)
            ent = bip39(0xFF, 32)  # "zoo ... vote"
            env = add(valid_case(nm, "step", n, step, PASS, 0x20, ent,
                                 expect_item={"type": "entropy", "hex": hx(ent)}, extra=words_extra(ent)))
            if step == 0:
                base[n] = (env, PASS, nm)

    # Every kind. Entropy of all five lengths, both sizes (the 24-word one is the step 0 case).
    for n in (53, 62):
        for kind, ln in sorted(ENTROPY_LEN.items()):
            if kind == 0x20:
                continue
            nm = "entropy-%dw-%d" % (ln * 3 // 4, n)
            ent = bip39(KIND_BYTE[kind], ln)
            add(valid_case(nm, "kind", n, 0, PASS, kind, ent,
                           expect_item={"type": "entropy", "hex": hx(ent)}, extra=words_extra(ent)))
        nm = "raw-key-%d" % n
        key = shake("key " + nm, 32)
        add(valid_case(nm, "kind", n, 0, PASS, 0x50, key, expect_item={"type": "raw_key", "hex": hx(key)}))
        r = SIZES[n][0]
        longest = r - 1
        for kind, label, tname in ((0x40, "passphrase", "passphrase"), (0x41, "note", "note")):
            for how, text in (
                ("shortest", "x"),
                ("longest", ("0123456789abcdefghijklmnopqrstuvwxyz"[:longest])),
                ("non-ascii", "Zoë café 日本語 ✓"),
            ):
                b = text.encode("utf-8")
                assert 1 <= len(b) <= longest
                nm = "%s-%s-%d" % (label, how, n)
                add(valid_case(nm, "kind", n, 0, PASS, kind, bytes([len(b)]) + b,
                               expect_item={"type": tname, "text": text},
                               extra={"text_bytes": len(b)}))
        # A longest text that is multi-byte, ending exactly at the room.
        text = "é" * (longest // 2) + ("a" if longest % 2 else "")
        b = text.encode("utf-8")
        assert len(b) == longest
        nm = "note-longest-multibyte-%d" % n
        add(valid_case(nm, "kind", n, 0, PASS, 0x41, bytes([len(b)]) + b,
                       expect_item={"type": "note", "text": text}, extra={"text_bytes": len(b)}))

    # All-zero and all-one seeds.
    for n, ln, kind in ((53, 16, 0x10), (62, 16, 0x10), (53, 32, 0x20), (62, 32, 0x20)):
        for label, byte in (("zero", 0x00), ("ones", 0xFF)):
            ent = bip39(byte, ln)
            nm = "%s-seed-%dw-%d" % (label, ln * 3 // 4, n)
            add(valid_case(nm, "seed", n, 0, PASS, kind, ent,
                           expect_item={"type": "entropy", "hex": hx(ent)}, extra=words_extra(ent)))

    # A passphrase that is not ASCII, in NFC and in NFD: one envelope.
    for n in (53, 62):
        ent = bip39(0x80, 24)
        salt = salt_of("unicode-%d" % n)
        envs = []
        for form, pp in (("nfc", UNI), ("nfd", UNI_NFD)):
            nm = "unicode-%s-%d" % (form, n)
            envs.append(add(valid_case(nm, "unicode", n, 0, pp, 0x18, ent,
                                       expect_item={"type": "entropy", "hex": hx(ent)}, salt=salt,
                                       pad_name="unicode-%d" % n,
                                       extra=dict(words_extra(ent), passphrase_utf8=hx(pp.encode())))))
        assert envs[0] == envs[1]
    # A compatibility character is kept: "fine" and "ﬁne" are two passphrases.
    n = 53
    nm = "unicode-compat-fine-53"
    ent = bip39(0x7F, 16)
    env = add(valid_case(nm, "unicode", n, 0, "fine", 0x10, ent,
                         expect_item={"type": "entropy", "hex": hx(ent)}, extra=words_extra(ent)))
    cases.append(fail_case("unicode-compat-ligature-53", "fail", env, "ﬁne", "does_not_open",
                           "NFC keeps the ligature, so it is a different passphrase from fine",
                           source=nm))

    # codex32 strings from BIP 93's vectors.
    bip = json.load(open(os.path.join(ROOT, "reference", "bip93", "vectors.json")))
    strings = []

    def take(group, s):
        if len(s) <= 93 and s not in [x[1] for x in strings]:
            strings.append((group, s))

    for e in bip["secrets"]:
        if e["vector"] != "5":  # 64 bytes: does not fit
            take("vector %s" % e["vector"], e["string"])
    for e in bip["sets"]:
        for s in e["shares"]:
            take("vector %s" % e["vector"], s)
        for s in e["derived"].values():
            take("vector %s" % e["vector"], s)
        take("vector %s" % e["vector"], e["secret"])
    for e in bip["alternates"]:
        for s in e["strings"]:
            take("vector %s" % e["vector"], s)
    firsts = set()
    for i, (grp, s) in enumerate(strings):
        item, mask, size, nbytes = codex_item(s)
        sizes = [53, 62] if nbytes <= 32 else [62]
        if nbytes <= 32 and grp not in firsts:
            firsts.add(grp)
        else:
            sizes = sizes[:1]
        for n in sizes:
            nm = "codex32-%02d-%s-%d" % (i, grp.replace(" ", ""), n)
            add(valid_case(nm, "codex32", n, 0, PASS, 0x30, item, unused_mask=mask,
                           expect_item={"type": "codex32", "string": s,
                                        "is_secret": s.lower()[3 + 5] == "s"},
                           extra={"source": "BIP 93 " + grp, "codex32_size": size,
                                  "item_length": nbytes}))
    writer_refuses = [
        {"string": [e for e in bip["secrets"] if e["vector"] == "5"][0]["string"],
         "reason": "BIP 93 vector 5, a 64-byte seed: 103 characters of payload, over the largest form"},
        {"string": bip["invalid"]["strings"][0] if isinstance(bip["invalid"], dict) else bip["invalid"][0]["strings"][0],
         "reason": "BIP 93's first invalid string: the checksum is wrong"},
    ]

    # Must fail: the base 24-word envelopes changed one way at a time.
    for n in (53, 62):
        env, pp, src = base[n]
        r, t = SIZES[n]

        def flip(i, bit=0x01):
            b = bytearray(env)
            b[i] ^= bit
            return bytes(b)

        cases.append(fail_case("fail-wrong-passphrase-%d" % n, "fail", env, PASS + "!", "does_not_open",
                               "a wrong passphrase", src))
        cases.append(fail_case("fail-header-step-bit-%d" % n, "fail", flip(0), PASS, "does_not_open",
                               "the step changed from 0 to 1: a different memory, a different key and tag", src))
        cases.append(fail_case("fail-header-marker-bit-%d" % n, "fail", flip(0, 0x80), PASS, "not_recognised",
                               "a bit of the marker changed: the first byte is 0x78", src))
        cases.append(fail_case("fail-salt-bit-%d" % n, "fail", flip(1), PASS, "does_not_open",
                               "a bit of the salt changed", src))
        cases.append(fail_case("fail-c-bit-%d" % n, "fail", flip(17), PASS, "does_not_open",
                               "a bit of the encrypted item changed", src))
        cases.append(fail_case("fail-tag-bit-%d" % n, "fail", flip(n - 1), PASS, "does_not_open",
                               "a bit of the tag changed", src))
        for h in (0xFD, 0xFE, 0xFF):
            cases.append(fail_case("fail-reserved-step-%d-%d" % (h & 7, n), "fail", bytes([h]) + env[1:], PASS,
                                   "not_recognised", "step %d is reserved: the first byte is 0x%02X" % (h & 7, h), src))
        cases.append(fail_case("fail-marker-11110-%d" % n, "fail", bytes([0xF0]) + env[1:], PASS, "not_recognised",
                               "marker 0b11110, which a later version would use: the first byte is 0xF0", src))
    e53, e62 = base[53][0], base[62][0]
    cases.append(fail_case("fail-length-52", "fail", e53[:52], PASS, "not_recognised",
                           "52 bytes: the 53-byte envelope with its last byte removed", base[53][2]))
    cases.append(fail_case("fail-length-54", "fail", e53 + b"\x00", PASS, "not_recognised",
                           "54 bytes: the 53-byte envelope with a zero byte added", base[53][2]))
    cases.append(fail_case("fail-length-61", "fail", e62[:61], PASS, "not_recognised",
                           "61 bytes: the 62-byte envelope with its last byte removed", base[62][2]))
    cases.append(fail_case("fail-length-63", "fail", e62 + b"\x00", PASS, "not_recognised",
                           "63 bytes: the 62-byte envelope with a zero byte added", base[62][2]))
    cases.append(fail_case("fail-62-cut-to-53", "fail", e62[:53], PASS, "does_not_open",
                           "the first 53 bytes of a 62-byte envelope: the length byte N is 53, and the bytes read as C and tag are not the ones sealed",
                           base[62][2]))
    # A tag made with the other size's length byte N, on the right fields.
    for n, other in ((62, 53), (53, 62)):
        env, pp, src = base[n]
        r, t = SIZES[n]
        d = derive(pp, env[1:17], 0)
        wrong = tag(d["k_mac"], env[0], other, env[1:17], 0x20, env[17:17 + r], t)
        mutated = env[:17 + r] + wrong
        cases.append(fail_case("fail-tag-with-n-%d-on-%d" % (other, n), "fail", mutated, pp, "does_not_open",
                               "the tag is HMAC over the message with N = %d instead of %d, cut to %d bytes: a tag made at one size does not open the other" % (other, n, t),
                               src))

    # Must fail with the right tag: made with the key.
    for n in (53, 62):
        r, _ = SIZES[n]
        pad = lambda label, head: head + shake("padding crafted-%s-%d" % (label, n), r - len(head))
        # len of 0 and one past the room (len = room is one past the largest, room - 1).
        cases.append(crafted_case("tag-ok-note-len-0-%d" % n, 0x41, n, pad("len0", b"\x00"), PASS, "len is 0"))
        cases.append(crafted_case("tag-ok-passphrase-len-0-%d" % n, 0x40, n, pad("plen0", b"\x00"), PASS, "len is 0"))
        cases.append(crafted_case("tag-ok-note-len-past-room-%d" % n, 0x41, n, pad("lenr", bytes([r])), PASS,
                                  "len is %d, one past the longest allowed, room - 1 = %d" % (r, r - 1)))
        cases.append(crafted_case("tag-ok-passphrase-len-past-room-%d" % n, 0x40, n, pad("plenr", bytes([r])), PASS,
                                  "len is %d, one past the longest allowed, room - 1 = %d" % (r, r - 1)))
        cases.append(crafted_case("tag-ok-note-not-utf8-%d" % n, 0x41, n, pad("utf8", b"\x03\xff\xfe\xfd"), PASS,
                                  "the 3 bytes of text 0xFF 0xFE 0xFD are not UTF-8"))
        cases.append(crafted_case("tag-ok-passphrase-truncated-utf8-%d" % n, 0x40, n, pad("utf8b", b"\x02\xc3\x28"), PASS,
                                  "the 2 bytes of text 0xC3 0x28 are not UTF-8"))
        ident = [CHARSET.index(ch) for ch in "test"]
        payload = [CHARSET.index("x")] * 26
        s_idx, a_idx = CHARSET.index("s"), CHARSET.index("a")

        def cx(size, threshold, index):
            nbits = 4 + 5 * (1 + 4 + 1 + 26)
            v = codex_p(size, 0, threshold, ident, index, payload)
            nb = (nbits + 7) // 8
            head = (v << (nb * 8 - nbits)).to_bytes(nb, "big")
            return head + shake("padding crafted-cx-%d-%d-%d-%d" % (size, threshold, index, n), r - nb)

        for size in (5, 6, 7):
            cases.append(crafted_case("tag-ok-codex32-size-%d-%d" % (size, n), 0x30, n, cx(size, 15, s_idx), PASS,
                                      "codex32 size %d is reserved" % size))
        if n == 53:
            for size, ln in ((3, 33), (4, 37)):
                p = bytes([(size << 5) | 0x05]) + shake("padding crafted-sz%d" % size, 31)
                cases.append(crafted_case("tag-ok-codex32-size-%d-%d" % (size, n), 0x30, n, p, PASS,
                                          "codex32 size %d needs %d bytes, over the 32-byte room" % (size, ln)))
        cases.append(crafted_case("tag-ok-codex32-threshold-1-%d" % n, 0x30, n, cx(0, 1, s_idx), PASS,
                                  "the threshold field holds the value 1 (the character p), which is neither 0 nor 2 to 9"))
        cases.append(crafted_case("tag-ok-codex32-threshold-0-index-a-%d" % n, 0x30, n, cx(0, CHARSET.index("0"), a_idx), PASS,
                                  "threshold 0 with the index a, not s"))
        # The same string with threshold 0 and index s is valid: it is vector 1's shape.

    # Must not be recognised: KEF version 20 envelopes, built from the KEF specification
    # (https://github.com/bitcoinpasada/faraday/blob/main/docs/KEF.md).
    kef = []
    for nm, id_len in (("kef-v20-empty-id-53", 0), ("kef-v20-9-byte-id-62", 9)):
        kid = shake("kef id " + nm, id_len) if id_len else b""
        kpass = "kef vector passphrase"
        count_field = 10  # 10 * 10,000 = 100,000 iterations
        key = hashlib.pbkdf2_hmac("sha256", kpass.encode(), kid, count_field * 10000, 32)
        iv = shake("kef iv " + nm, 12)
        plain = shake("kef plaintext " + nm, 32)
        ct_tag = AESGCM(key).encrypt(iv, plain, None)
        payload = iv + ct_tag[:32] + ct_tag[32:36]
        env = bytes([id_len]) + kid + bytes([20]) + count_field.to_bytes(3, "big") + payload
        assert len(env) == (53 if id_len == 0 else 62)
        kef.append({
            "name": nm, "group": "not-recognised", "size": len(env), "envelope": hx(env),
            "expect": {"outcome": "not_recognised",
                       "reason": "a KEF version 20 envelope: its first byte is the id length, 0x%02X, below 0xF8" % id_len},
            "kef": {"id": hx(kid), "version": 20, "iterations_field": count_field, "iterations": count_field * 10000,
                    "passphrase": kpass, "plaintext": hx(plain), "iv": hx(iv), "tag_bytes": 4},
        })
        assert read(env, "x")["outcome"] == "not_recognised"
    cases += kef

    # The 32-byte size (25 x 25): the three kinds it holds, then what fails.
    # Added after every case above so that those keep their places in the file.
    n = 32
    r, t = SIZES[n]
    sl = SALT_LEN[n]
    for step in range(5):
        nm = "step-%d-12w-%d" % (step, n)
        ent = bip39(0x00, 16)  # "abandon ... about"
        env = add(valid_case(nm, "step", n, step, PASS, 0x10, ent,
                             expect_item={"type": "entropy", "hex": hx(ent)}, extra=words_extra(ent)))
        if step == 0:
            base[n] = (env, PASS, nm)
    for kind, label, tname in ((0x40, "passphrase", "passphrase"), (0x41, "note", "note")):
        for how, text in (
            ("shortest", "x"),
            ("longest", "0123456789abcdefghijklmnopqrstuvwxyz"[:r - 1]),
            ("non-ascii", "Zoë ✓ 日本"),
        ):
            b = text.encode("utf-8")
            assert 1 <= len(b) <= r - 1
            nm = "%s-%s-%d" % (label, how, n)
            add(valid_case(nm, "kind", n, 0, PASS, kind, bytes([len(b)]) + b,
                           expect_item={"type": tname, "text": text}, extra={"text_bytes": len(b)}))
    text = "é" * ((r - 1) // 2) + "a"
    b = text.encode("utf-8")
    assert len(b) == r - 1
    nm = "note-longest-multibyte-%d" % n
    add(valid_case(nm, "kind", n, 0, PASS, 0x41, bytes([len(b)]) + b,
                   expect_item={"type": "note", "text": text}, extra={"text_bytes": len(b)}))
    for label, byte in (("zero", 0x00), ("ones", 0xFF)):
        ent = bip39(byte, 16)
        nm = "%s-seed-12w-%d" % (label, n)
        add(valid_case(nm, "seed", n, 0, PASS, 0x10, ent, expect_item={"type": "entropy", "hex": hx(ent)},
                       extra=words_extra(ent)))
    ent = bip39(0x80, 16)
    salt = salt_of("unicode-%d" % n, n)
    envs = []
    for form, pp in (("nfc", UNI), ("nfd", UNI_NFD)):
        nm = "unicode-%s-%d" % (form, n)
        envs.append(add(valid_case(nm, "unicode", n, 0, pp, 0x10, ent,
                                   expect_item={"type": "entropy", "hex": hx(ent)}, salt=salt,
                                   pad_name="unicode-%d" % n,
                                   extra=dict(words_extra(ent), passphrase_utf8=hx(pp.encode())))))
    assert envs[0] == envs[1]

    env, pp, src = base[n]

    def flip32(i, bit=0x01):
        b = bytearray(env)
        b[i] ^= bit
        return bytes(b)

    cases.append(fail_case("fail-wrong-passphrase-32", "fail", env, PASS + "!", "does_not_open",
                           "a wrong passphrase", src))
    cases.append(fail_case("fail-header-step-bit-32", "fail", flip32(0), PASS, "does_not_open",
                           "the step changed from 0 to 1: a different memory, a different key and tag", src))
    cases.append(fail_case("fail-header-marker-bit-32", "fail", flip32(0, 0x80), PASS, "not_recognised",
                           "a bit of the marker changed: the first byte is 0x78", src))
    cases.append(fail_case("fail-salt-bit-32", "fail", flip32(1), PASS, "does_not_open",
                           "a bit of the salt changed", src))
    cases.append(fail_case("fail-c-bit-32", "fail", flip32(1 + sl), PASS, "does_not_open",
                           "a bit of the encrypted item changed", src))
    cases.append(fail_case("fail-tag-bit-32", "fail", flip32(n - 1), PASS, "does_not_open",
                           "a bit of the tag changed", src))
    for h in (0xFD, 0xFE, 0xFF):
        cases.append(fail_case("fail-reserved-step-%d-32" % (h & 7), "fail", bytes([h]) + env[1:], PASS,
                               "not_recognised", "step %d is reserved: the first byte is 0x%02X" % (h & 7, h), src))
    cases.append(fail_case("fail-marker-11110-32", "fail", bytes([0xF0]) + env[1:], PASS, "not_recognised",
                           "marker 0b11110, which a later version would use: the first byte is 0xF0", src))
    cases.append(fail_case("fail-length-31", "fail", env[:31], PASS, "not_recognised",
                           "31 bytes: the 32-byte envelope with its last byte removed", src))
    cases.append(fail_case("fail-length-33", "fail", env + b"\x00", PASS, "not_recognised",
                           "33 bytes: the 32-byte envelope with a zero byte added", src))
    cases.append(fail_case("fail-53-cut-to-32", "fail", base[53][0][:32], PASS, "does_not_open",
                           "the first 32 bytes of a 53-byte envelope: the length byte N is 32, the salt is read as 11 bytes, and the bytes read as C and tag are not the ones sealed",
                           base[53][2]))
    # A tag made with the other length byte N: 53 on the 32-byte envelope, 32 on the 53-byte one.
    d = derive(PASS, env[1:1 + sl], 0)
    wrong = tag(d["k_mac"], env[0], 53, env[1:1 + sl], 0x10, env[1 + sl:1 + sl + r], t)
    cases.append(fail_case("fail-tag-with-n-53-on-32", "fail", env[:1 + sl + r] + wrong, PASS, "does_not_open",
                           "the tag is HMAC over the message with N = 53 instead of 32, cut to 4 bytes: a tag made at one size does not open the other",
                           src))
    e53 = base[53][0]
    d53 = derive(PASS, e53[1:17], 0)
    wrong = tag(d53["k_mac"], e53[0], 32, e53[1:17], 0x20, e53[17:49], 4)
    cases.append(fail_case("fail-tag-with-n-32-on-53", "fail", e53[:49] + wrong, PASS, "does_not_open",
                           "the tag is HMAC over the message with N = 32 instead of 53, cut to 4 bytes: a tag made at one size does not open the other",
                           base[53][2]))
    # A right tag for a kind this size does not hold: the reader does not test it.
    for kind in (0x20, 0x30, 0x50):
        nm = "fail-kind-%02X-not-at-32" % kind
        salt = salt_of(nm, n)
        d = derive(PASS, salt, 0)
        p = shake("padding " + nm, r)
        c = xor(p, d["keystream"][:r])
        envk = bytes([0xF8]) + salt + c + tag(d["k_mac"], 0xF8, n, salt, kind, c, t)
        assert all(tag(d["k_mac"], 0xF8, n, salt, k, c, t) != envk[-t:] for k in KINDS_AT[n])
        cases.append(fail_case(nm, "fail", envk, PASS, "does_not_open",
                               "the tag is right for kind %s (%s), which the 32-byte size does not hold, so a reader does not test it" % (kh(kind), KIND_NAME[kind]),
                               note="made with the key: P is %s, and the tag is HMAC over H || N || salt || %s || C" % (hx(p), kh(kind))))
    # Right tags over a P the format refuses.
    pad32 = lambda label, head: head + shake("padding crafted-%s-%d" % (label, n), r - len(head))
    cases.append(crafted_case("tag-ok-note-len-0-32", 0x41, n, pad32("len0", b"\x00"), PASS, "len is 0"))
    cases.append(crafted_case("tag-ok-passphrase-len-0-32", 0x40, n, pad32("plen0", b"\x00"), PASS, "len is 0"))
    cases.append(crafted_case("tag-ok-note-len-past-room-32", 0x41, n, pad32("lenr", bytes([r])), PASS,
                              "len is %d, one past the longest allowed, room - 1 = %d" % (r, r - 1)))
    cases.append(crafted_case("tag-ok-passphrase-len-past-room-32", 0x40, n, pad32("plenr", bytes([r])), PASS,
                              "len is %d, one past the longest allowed, room - 1 = %d" % (r, r - 1)))
    cases.append(crafted_case("tag-ok-note-not-utf8-32", 0x41, n, pad32("utf8", b"\x03\xff\xfe\xfd"), PASS,
                              "the 3 bytes of text 0xFF 0xFE 0xFD are not UTF-8"))
    # Must not be recognised: KEF version 5 with an 8-character id and 12 words, 32 bytes.
    nm = "kef-v5-8-char-id-32"
    kid = b"73c5da0a"  # a fingerprint's form: 8 hex characters
    kpass = "kef vector passphrase"
    count_field = 10
    key = hashlib.pbkdf2_hmac("sha256", kpass.encode(), kid, count_field * 10000, 32)
    plain = shake("kef plaintext " + nm, 16)
    assert plain[-1] != 0
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ct = ecb.update(plain) + ecb.finalize()
    check = hashlib.sha256(bytes([5]) + plain + key).digest()[:3]
    envk = bytes([len(kid)]) + kid + bytes([5]) + count_field.to_bytes(3, "big") + ct + check
    assert len(envk) == 32
    assert read(envk, "x")["outcome"] == "not_recognised"
    cases.append({
        "name": nm, "group": "not-recognised", "size": 32, "envelope": hx(envk),
        "expect": {"outcome": "not_recognised",
                   "reason": "a KEF version 5 envelope: its first byte is the id length, 0x08, below 0xF8"},
        "kef": {"id": hx(kid), "id_text": kid.decode(), "version": 5, "iterations_field": count_field,
                "iterations": count_field * 10000, "passphrase": kpass, "plaintext": hx(plain), "check_bytes": 3},
    })
    writer_refuses += [
        {"size": 32, "kind": "0x20", "item": {"type": "entropy", "hex": hx(bip39(0x00, 32))},
         "reason": "24 words of entropy: 32 bytes, over the 16-byte room of the 32-byte size"},
        {"size": 32, "kind": "0x41", "item": {"type": "note", "text": "0123456789abcdef"},
         "reason": "a note of 16 bytes of text: 17 item bytes, over the 16-byte room"},
        {"size": 32, "kind": "0x30", "item": {"type": "codex32", "string": [s for _, s in strings if len(s) == 48][0]},
         "reason": "a 128-bit codex32 string: 21 item bytes, and the kind is not held at the 32-byte size"},
    ]

    # The QR code of one vector at each size.
    qrs = []
    pngs = {}
    for n in (53, 62, 32):
        env, pp, nm = base[n]
        qr = qr_of(env)
        size = qr.get_size()
        pngs["qr-%d.png" % n] = png_of(qr)
        entry = {"case": nm, "envelope": hx(env), "bytes": n}
        if n == 32:
            entry["text"] = text_of(env)
        entry.update({
            "version": qr.get_version(), "modules": size, "level": "M" if n == 62 else "L",
            "mask": qr.get_mask(),
            "segment": "one alphanumeric-mode segment of 47 characters, no ECI" if n == 32
            else "one byte-mode segment, no ECI",
            "png": "qr-%d.png" % n, "png_sha256": hashlib.sha256(pngs["qr-%d.png" % n]).hexdigest(),
            "matrix": ["".join("1" if qr.get_module(x, y) else "0" for x in range(size)) for y in range(size)],
            "matrix_note": "one string per row, top to bottom, 1 is a dark module, no quiet zone",
        })
        qrs.append(entry)
        assert size == {32: 25, 53: 29, 62: 33}[n]

    # The 32-byte size's text form in a QR code (§3, §9): what a reader decodes and what it refuses.
    env, pp, src = base[32]
    good = text_of(env)
    assert envelope_of_text(good) == (env, None) and good[0] == "A"
    over = ""
    v = 256 ** 32
    for _ in range(TEXT_LEN):
        v, d = divmod(v, 45)
        over = QR_ALNUM[d] + over
    assert v == 0
    ent32 = [c for c in cases if c["name"] == src][0]["expect"]
    text_cases = [
        {"name": "text-valid-32", "text": good, "passphrase": PASS, "source": src,
         "expect": {"outcome": "opens", "envelope": hx(env), "kind": ent32["kind"], "item": ent32["item"]}},
        {"name": "text-over-256-32", "text": over,
         "expect": {"outcome": "not_recognised",
                    "reason": "the 47 characters stand for 256^32 exactly, the least value that is not 32 bytes"}},
        {"name": "text-46-characters", "text": good[:-1],
         "expect": {"outcome": "not_recognised", "reason": "46 characters: the valid text with its last one removed"}},
        {"name": "text-48-characters", "text": "0" + good,
         "expect": {"outcome": "not_recognised",
                    "reason": "48 characters: the valid text with a 0 before it, the same value but not 47 characters"}},
        {"name": "text-lower-case", "text": "a" + good[1:],
         "expect": {"outcome": "not_recognised",
                    "reason": "its first letter is a lower-case a: not in the alphabet, and not read as A"}},
        {"name": "text-outside-alphabet", "text": good[:20] + "#" + good[21:],
         "expect": {"outcome": "not_recognised", "reason": "its 21st character is #, which is not in the alphabet"}},
    ]
    ktext = base43_of(envk)
    assert len(ktext) == TEXT_LEN and ktext[0] in "0123456789"
    text_cases.append(
        {"name": "text-kef-v5-base43", "text": ktext, "source": "kef-v5-8-char-id-32",
         "expect": {"outcome": "not_recognised",
                    "reason": "the KEF version 5 envelope of kef-v5-8-char-id-32 as Krux's base43 text: read as "
                              "AQRV's base 45 it is 32 bytes whose first byte is 0x%02X, below 0xF8"
                              % envelope_of_text(ktext)[0][0]}})
    for tc in text_cases:
        got = read_text(tc["text"], tc.get("passphrase", "x"))
        assert got["outcome"] == tc["expect"]["outcome"], (tc["name"], got)

    # The 37-byte size and the words form (§3.2). Added after every case above so that those keep their places.
    _words_selftest()
    c37, base[37] = build_37()
    cases += c37
    for c in cases:
        if c["size"] == 37 or (c["size"] in (53, 62) and c["expect"]["outcome"] == "opens"):
            c["words"] = words_of(bytes.fromhex(c["envelope"]))
            got = read_words(c["words"], c["passphrase"])
            assert got["outcome"] == c["expect"]["outcome"], (c["name"], got)
            if got["outcome"] == "opens":
                assert (got["unreadable"], got["wrong"], got["envelope"], got["kind"], got["item"]) == (
                    [], [], c["envelope"], c["expect"]["kind"], c["expect"]["item"]), c["name"]
    case_of = {c["name"]: c for c in cases}
    words_bases = {n: base[n] + (case_of[base[n][2]]["expect"],) for n in (37, 53, 62)}
    words_cases = build_words(words_bases)
    words_text_cases = build_words_text(words_bases)

    doc = {
        "about": "Test vectors for the Argon QR Vault (AQRV), AQRV.md section 11. See README.md. Written by gen.py.",
        "parameters": {
            "argon2id": {"passes": 3, "lanes": 4, "output_bytes": 32, "version": "0x13"},
            "steps": [{"step": s, "header": "0x%02X" % (0xF8 | s), "memory_kib": m} for s, m in STEPS.items()],
            "labels": {"enc": LABEL_ENC.decode(), "mac": LABEL_MAC.decode()},
            "sizes": [{"bytes": n, "salt_bytes": SALT_LEN[n], "room": r, "tag_bytes": t,
                       "kinds": [kh(k) for k in KINDS_AT[n]]} for n, (r, t) in SIZES.items()],
            "kinds": [{"kind": kh(k), "name": nme} for k, nme, _ in KINDS],
            "outcomes": {
                "opens": "recognised, one kind's tag matches, the item reads: expect.kind and expect.item are what a reader shows",
                "does_not_open": "recognised, asks for the passphrase, and reports that the code does not open",
                "not_recognised": "not treated as AQRV: no passphrase is asked for",
                "words_do_not_check": "words only: the words fail their check and no correction with 2e + f <= 4 makes them pass; no passphrase is asked for, and the reader says so in words distinct from does_not_open",
                "ambiguous": "words from text only: readings of the text give different envelopes, or one gives an envelope and another is not AQRV words; no passphrase is asked for",
                "too_many": "words from text only: text over 16384 bytes, a run with more than 1024 cuts, or more than 1024 readings; no passphrase is asked for",
                "not_aqrv_words": "words only: other than 36, 48 or 56 words, or words that check but whose unused bits are not 0 or whose step is not defined; no passphrase is asked for",
            },
            "words": {
                "word_list": "reference/python-shamir-mnemonic/wordlist.txt, SLIP-0039's list, one word per line; a word's value is its line counted from 0",
                "word_list_sha256": WORDLIST_SHA256,
                "field": "GF(1024): polynomials over GF(2) modulo x^10 + x^3 + 1 (0x409)",
                "a": 2,
                "generator": ["0x%03X" % g for g in WORDS_GENERATOR],
                "generator_note": "g(x) = (x - a)(x - a^2)...(x - a^6), coefficients highest power first",
                "customization_string": WORDS_CS.decode(),
                "check_words": WORDS_CHECK,
                "check": "polymod(cs || data || six 0) XOR 1, the register starting at 1",
                "sizes": [{"bytes": n, "bits_written": b, "data_words": m, "check_words": WORDS_CHECK,
                           "words": m + WORDS_CHECK, "unused_bits": u} for n, (b, m, u) in WORDS_TABLE.items()],
                "correction_rule": "2e + f <= 4, e wrong words changed and f unreadable positions filled",
            },
            "words_text": {
                "max_text_bytes": TEXT_MAX_BYTES,
                "max_cuts_of_a_run": TEXT_MAX_CUTS,
                "max_readings": TEXT_MAX_READINGS,
                "max_positions": TEXT_MAX_POSITIONS,
                "piece_letters": [4, 8],
                "marks": ["U+%04X-U+%04X" % r for r in MARK_RANGES],
                "letter": "Unicode's Alphabetic property",
            },
        },
        "cases": cases,
        "writer_refuses": writer_refuses,
        "qr": qrs,
        "qr_text": text_cases,
        "words": words_cases,
        "words_text": words_text_cases,
    }
    text = json.dumps(doc, indent=1, ensure_ascii=True) + "\n"
    out = {"aqrv.json": text.encode()}
    out.update(pngs)
    return out, (len(cases), len(words_cases), len(words_text_cases))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="compare with the files, write nothing")
    args = ap.parse_args()
    t0 = time.time()
    files, n = build()
    bad = 0
    for name, data in files.items():
        path = os.path.join(HERE, name)
        if args.check:
            have = open(path, "rb").read() if os.path.exists(path) else None
            if have != data:
                print("differs: " + name)
                bad += 1
        else:
            with open(path, "wb") as f:
                f.write(data)
    print("%d cases, %d words cases, %d words_text cases, %d files, %.1f s%s" % (n[0], n[1], n[2], len(files), time.time() - t0, ", all identical" if args.check and not bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
