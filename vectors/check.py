#!/usr/bin/env python3
"""A second reader and writer for the Argon QR Vault (AQRV), written from
AQRV.md section 2 to 10 alone, and run over every case of aqrv.json,
the 32-byte size's text forms, the words and the QR pictures.

It takes an envelope and a passphrase and answers: not recognised; refused,
and why; or opened, with the fields. It also seals: for each case that opens,
the same inputs (passphrase, step, size, kind, item, salt, padding) must give
the same envelope.

Libraries other than gen.py's: PyCA cryptography's Argon2id; HKDF-Expand and
HMAC-SHA-256 over Python's hmac and hashlib; ChaCha20 written out below from
RFC 8439 and checked against its section 2.4.2 vector before anything else.

The words (section 3.2): GF(1024) and an errors-and-erasures Reed-Solomon
decoder written out below (syndromes, Berlekamp-Massey started from the
erasure locator, Chien search over the written positions, Forney). Before
anything else it checks that a = 2 has order 1023, that section 3.2's
generator is the product of its six roots, that the three-root form is
SLIP-0039's rs1024_polymod (copied from SLIP-0039) on 3000 inputs, and that
the decoder recovers random code words at every 2e + f <= 6. It writes every
case's words from its envelope and reads them back, and reads every list of
words and every text of words (section 3.2, reading words from text) against
its expect. Where reedsolo is installed, every list that
needs correcting is also decoded through it (the code word 1 || cs || words
with the last XOR 1, a mapping checked by encoding first) and must give the
same answer.

    python3 -I -B vectors/check.py [--no-qr]
    uv run --no-project --with cryptography --with reedsolo python3 -I -B vectors/check.py --no-qr

Prints a one-line count and every disagreement; exits 1 on any. Written by
Faraday's authors, so it is a second reader and not the outside
implementation AQRV.md section 11 asks for.
"""

import functools
import hashlib
import hmac
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import unicodedata
import zlib

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- ChaCha20


def _rotl(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_block(key, counter, nonce):
    init = (
        [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
        + list(struct.unpack("<8I", key))
        + [counter & 0xFFFFFFFF]
        + list(struct.unpack("<3I", nonce))
    )
    s = list(init)
    for _ in range(10):
        _quarter(s, 0, 4, 8, 12)
        _quarter(s, 1, 5, 9, 13)
        _quarter(s, 2, 6, 10, 14)
        _quarter(s, 3, 7, 11, 15)
        _quarter(s, 0, 5, 10, 15)
        _quarter(s, 1, 6, 11, 12)
        _quarter(s, 2, 7, 8, 13)
        _quarter(s, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(s, init)])


def chacha20_stream(key, counter, nonce, n):
    out = b""
    while len(out) < n:
        out += chacha20_block(key, counter, nonce)
        counter += 1
    return out[:n]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def chacha20_self_test():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    want = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    )
    return xor(pt, chacha20_stream(key, 1, nonce, len(pt))) == want


# ---------------------------------------------------------------- the format

STEP_KIB = {0: 65536, 1: 131072, 2: 262144, 3: 524288, 4: 1048576}
SIZES = {32: (16, 4), 37: (16, 4), 53: (32, 4), 62: (37, 8)}  # envelope length -> room, tag length
SALT = {32: 11, 37: 16, 53: 16, 62: 16}  # envelope length -> salt length
KINDS = [0x10, 0x14, 0x18, 0x1C, 0x20, 0x30, 0x40, 0x41, 0x50]
KINDS_OF = {32: [0x10, 0x40, 0x41], 37: [0x10, 0x40, 0x41], 53: KINDS, 62: KINDS}  # the kinds each size holds and tests
ENTROPY = {0x10: 16, 0x14: 20, 0x18: 24, 0x1C: 28, 0x20: 32}
LABEL_ENC = b"argon-qr-vault-1 enc"
LABEL_MAC = b"argon-qr-vault-1 mac"

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"  # BIP-173 values
CODEX_SIZE = {0: (26, 21), 1: (32, 25), 2: (39, 29), 3: (45, 33), 4: (52, 37)}  # c, item bytes
CODEX_LEN = {22 + c: s for s, (c, _) in CODEX_SIZE.items()}  # string length -> size
GEN = [0x19DC500CE73FDE210, 0x1BFAE00DEF77FE529, 0x1FBD920FFFE7BEE52, 0x1739640BDEEE3FDAD, 0x07729A039CFC75F5A]
MS32_CONST = 0x10CE0795C2FD1E62A


def ms32_polymod(values):
    residue = 0x23181B3
    for v in values:
        b = residue >> 60
        residue = ((residue & 0x0FFFFFFFFFFFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                residue ^= GEN[i]
    return residue


def ms32_checksum(data):
    p = ms32_polymod(list(data) + [0] * 13) ^ MS32_CONST
    return [(p >> (5 * (12 - i))) & 31 for i in range(13)]


def hkdf_expand_one(prk, info):
    """RFC 5869 section 2.3, one block: T(1) = HMAC(PRK, info || 0x01)."""
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


@functools.lru_cache(maxsize=None)
def argon(pw, salt, kib):
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=kib).derive(pw)


def derive(passphrase, salt, kib):
    pw = unicodedata.normalize("NFC", passphrase).encode("utf-8")
    prk = argon(pw, salt, kib)
    return pw, prk, hkdf_expand_one(prk, LABEL_ENC), hkdf_expand_one(prk, LABEL_MAC)


def tags_for(k_mac, header, n, salt, c, t):
    out = {}
    for kind in KINDS_OF[n]:
        msg = bytes([header, n]) + salt + bytes([kind]) + c
        out[kind] = hmac.new(k_mac, msg, hashlib.sha256).digest()[:t]
    return out


# ---------------------------------------------------------------- reading


class Refused(Exception):
    """The item fails its kind's layout (section 6, reading, step 4)."""

    def __init__(self, rule):
        super().__init__(rule)
        self.rule = rule


def read_codex32(p):
    size = p[0] >> 5
    if size > 4:
        raise Refused("size")
    c, nbytes = CODEX_SIZE[size]
    if nbytes > len(p):
        raise Refused("room")
    upper = (p[0] >> 4) & 1
    nbits = 4 + 5 + 20 + 5 + 5 * c
    big = int.from_bytes(p[:nbytes], "big")
    chars = []
    for i in range(1 + 4 + 1 + c):
        shift = nbytes * 8 - 4 - 5 * (i + 1)
        chars.append((big >> shift) & 31)
    assert 4 + 5 * len(chars) == nbits
    threshold, index = chars[0], chars[5]
    if threshold not in [CHARSET.index(d) for d in "023456789"]:
        raise Refused("threshold")
    if threshold == CHARSET.index("0") and index != CHARSET.index("s"):
        raise Refused("threshold-index")
    text = "ms1" + "".join(CHARSET[v] for v in chars) + "".join(CHARSET[v] for v in ms32_checksum(chars))
    if upper:
        text = text.upper()
    return {"type": "codex32", "string": text, "is_secret": index == CHARSET.index("s")}


def read_text(p, typ):
    n = p[0]
    if n < 1 or n > len(p) - 1:
        raise Refused("len")
    try:
        text = bytes(p[1 : 1 + n]).decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("utf8") from None
    return {"type": typ, "text": text}


def read_item(kind, p):
    if kind in ENTROPY:
        return {"type": "entropy", "hex": p[: ENTROPY[kind]].hex()}
    if kind == 0x50:
        return {"type": "raw_key", "hex": p[:32].hex()}
    if kind == 0x30:
        return read_codex32(p)
    if kind == 0x40:
        return read_text(p, "passphrase")
    return read_text(p, "note")


def recognised(env):
    return len(env) in SIZES and 0xF8 <= env[0] <= 0xFC


QR_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"  # QR alphanumeric, index = digit


def text_to_envelope(s):
    """Section 9: the 32 bytes a 47-character code stands for, or None (not recognised)."""
    if len(s) != 47 or any(ch not in QR_ALPHABET for ch in s):
        return None
    v = functools.reduce(lambda a, ch: a * 45 + QR_ALPHABET.index(ch), s, 0)
    if v >> 256:
        return None
    return v.to_bytes(32, "big")


def envelope_to_text(env):
    """Section 3: a 32-byte envelope as 47 base-45 digits, most significant first."""
    v, out = int.from_bytes(env, "big"), []
    for _ in range(47):
        v, d = divmod(v, 45)
        out.append(QR_ALPHABET[d])
    return "".join(reversed(out))


def read(env, passphrase):
    """Returns (answer, values). answer is ("not_recognised",), ("no_match",),
    ("ambiguous",), ("layout", kind, rule) or ("opens", kind, item)."""
    if not recognised(env):
        return ("not_recognised",), {}
    header, n = env[0], len(env)
    room, t = SIZES[n]
    sl = SALT[n]
    salt, c, tag = env[1 : 1 + sl], env[1 + sl : 1 + sl + room], env[1 + sl + room :]
    pw, prk, k_enc, k_mac = derive(passphrase, salt, STEP_KIB[header & 7])
    ks = chacha20_stream(k_enc, 0, bytes(12), room)
    p = xor(c, ks)
    tags = tags_for(k_mac, header, n, salt, c, t)
    values = {
        "pw": pw.hex(), "PRK": prk.hex(), "K_enc": k_enc.hex(), "K_mac": k_mac.hex(),
        "keystream": ks.hex(), "P": p.hex(), "C": c.hex(), "tag": tag.hex(),
        "tags": {"0x%02X" % k: v.hex() for k, v in tags.items()},
        "hmac_message": {k: bytes([header, n]) + salt + bytes([k]) + c for k in KINDS_OF[n]},
    }
    hits = [k for k in KINDS_OF[n] if hmac.compare_digest(tags[k], tag)]
    if not hits:
        return ("no_match",), values
    if len(hits) > 1:
        return ("ambiguous",), values
    try:
        return ("opens", hits[0], read_item(hits[0], p)), values
    except Refused as e:
        return ("layout", hits[0], e.rule), values


# ---------------------------------------------------------------- writing


class WriterRefuses(Exception):
    pass


def codex32_item(s, fill):
    """The item bytes of a codex32 string (section 3.1); fill is the value
    that goes into the unused low bits of the last byte."""
    if s != s.lower() and s != s.upper():
        raise WriterRefuses("mixed case")
    low = s.lower()
    if len(s) not in CODEX_LEN or not low.startswith("ms1"):
        raise WriterRefuses("prefix or length")
    if any(ch not in CHARSET for ch in low[3:]):
        raise WriterRefuses("character")
    vals = [CHARSET.index(ch) for ch in low[3:]]
    if ms32_polymod(vals) != MS32_CONST:
        raise WriterRefuses("checksum")
    data = vals[:-13]
    if low[3] not in "023456789":
        raise WriterRefuses("threshold")
    if low[3] == "0" and low[3 + 5] != "s":
        raise WriterRefuses("threshold 0 and an index other than s")
    size = CODEX_LEN[len(s)]
    nbytes = CODEX_SIZE[size][1]
    bits = (size << 1) | (1 if s == s.upper() and s != s.lower() else 0)
    nb = 4
    for v in data:
        bits = (bits << 5) | v
        nb += 5
    spare = nbytes * 8 - nb
    if not 0 <= fill < (1 << spare) and fill != 0:
        raise WriterRefuses("fill")
    bits = (bits << spare) | fill
    return bits.to_bytes(nbytes, "big")


def item_bytes_for(kind, item, fill):
    if kind in ENTROPY or kind == 0x50:
        b = bytes.fromhex(item["hex"])
        want = ENTROPY.get(kind, 32)
        if len(b) != want:
            raise WriterRefuses("length")
        return b
    if kind == 0x30:
        return codex32_item(item["string"], fill)
    text = item["text"].encode("utf-8")
    if not text:
        raise WriterRefuses("empty text")
    return bytes([len(text)]) + text


def seal(passphrase, step, size, kind, item, salt, padding, fill=0):
    if not passphrase:
        raise WriterRefuses("empty passphrase")
    room, t = SIZES[size]
    if kind not in KINDS_OF[size]:
        raise WriterRefuses("kind not held at this size")
    if len(salt) != SALT[size]:
        raise WriterRefuses("salt length")
    ib = item_bytes_for(kind, item, fill)
    if len(ib) > room:
        raise WriterRefuses("does not fit")
    if len(padding) != room - len(ib):
        raise WriterRefuses("padding length")
    header = 0xF8 | step
    _, _, k_enc, k_mac = derive(passphrase, salt, STEP_KIB[step])
    c = xor(ib + padding, chacha20_stream(k_enc, 0, bytes(12), room))
    tags = tags_for(k_mac, header, size, salt, c, t)
    if any(tags[k] == tags[kind] for k in KINDS_OF[size] if k != kind):
        raise WriterRefuses("two kinds' tags agree")
    return bytes([header]) + salt + c + tags[kind]


# ---------------------------------------------------------------- words (section 3.2)

WORDLIST_SHA256 = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"
WORDLIST_PATH = os.path.join(HERE, "..", "reference", "python-shamir-mnemonic", "wordlist.txt")
GF_MOD = 0x409  # x^10 + x^3 + 1
GENERATOR = [0x001, 0x07E, 0x083, 0x34F, 0x110, 0x09E, 0x082]  # section 3.2's text, highest power first
CS = b"argon-qr-vault-1 words"
NCHECK = 6
WORDS_SIZE = {36: 37, 48: 53, 56: 62}  # number of words -> envelope length
RULE_LIMIT = 4  # 2e + f <= 4

GF_EXP, GF_LOG = [0] * 2046, [0] * 1024


def gf_tables():
    x = 1
    for i in range(1023):
        GF_EXP[i] = GF_EXP[i + 1023] = x
        GF_LOG[x] = i
        x <<= 1
        if x & 0x400:
            x ^= GF_MOD
    return x == 1 and len(set(GF_EXP[:1023])) == 1023  # a = 2 has order 1023


def gmul(a, b):
    return 0 if a == 0 or b == 0 else GF_EXP[GF_LOG[a] + GF_LOG[b]]


def ginv(a):
    return GF_EXP[1023 - GF_LOG[a]]


def apow(k):
    return GF_EXP[k % 1023]


def poly_eval(p, x):
    """p lowest power first."""
    y = 0
    for c in reversed(p):
        y = gmul(y, x) ^ c
    return y


def poly_mul(p, q):
    out = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            out[i + j] ^= gmul(a, b)
    return out


def generator_from_roots(k):
    """(x - a)(x - a^2)...(x - a^k), highest power first."""
    g = [1]  # lowest first
    for i in range(1, k + 1):
        g = poly_mul(g, [apow(i), 1])
    return list(reversed(g))


def polymod(values, gen):
    """Section 3.2: the remainder mod gen of 1 then values, highest power first,
    as one number of 10-bit symbols."""
    k = len(gen) - 1
    r = [0] * k
    for s in [1] + list(values):
        top = r[0]
        r = r[1:] + [s]
        for i in range(k):
            r[i] ^= gmul(top, gen[i + 1])
    return functools.reduce(lambda a, s: (a << 10) | s, r, 0)


SLIP39_GEN = [0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009,
              0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120]


def rs1024_polymod(values):
    """SLIP-0039's, copied from its text."""
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xFFFFF) << 10 ^ v
        for i in range(10):
            chk ^= SLIP39_GEN[i] if ((b >> i) & 1) else 0
    return chk


def words_self_test():
    """The field, the generator from its roots, and the 3-root form against
    SLIP-0039's constants; then the decoder on random codewords."""
    import random

    msgs = []
    if not gf_tables():
        return ["a = 2 does not have order 1023 mod x^10 + x^3 + 1"]
    if generator_from_roots(NCHECK) != GENERATOR:
        msgs.append("the generator's coefficients are not the product of its roots: %s"
                    % ["0x%03X" % c for c in generator_from_roots(NCHECK)])
    g3 = generator_from_roots(3)
    rnd = random.Random(1)
    for t in range(3000):
        cs = [b"shamir", b"shamir_extendable", CS][t % 3]
        data = [rnd.randrange(1024) for _ in range(rnd.randrange(0, 60))]
        v = list(cs) + data + [0] * 3
        if polymod(v, g3) != rs1024_polymod(v):
            msgs.append("the 3-root form differs from SLIP-0039's rs1024_polymod")
            break
    for n in WORDS_SIZE:
        for f in range(7):
            for e in range(4):
                if 2 * e + f > 6:
                    continue
                for _ in range(15):
                    data = [rnd.randrange(1024) for _ in range(n - NCHECK)]
                    good = data + check_words(data)
                    pos = rnd.sample(range(n), e + f)
                    vals = list(good)
                    for p in pos[:e]:
                        vals[p] ^= rnd.randrange(1, 1024)
                    for p in pos[e:]:
                        vals[p] = None
                    got = rs_correct(vals, 6)
                    if got is None or got[0] != good or sorted(got[1]) != sorted(pos[:e]):
                        msgs.append("the decoder misses %d wrong and %d unreadable at %d words" % (e, f, n))
                        break
    return msgs


def check_words(data):
    p = polymod(list(CS) + list(data) + [0] * NCHECK, GENERATOR) ^ 1
    return [(p >> (10 * (NCHECK - 1 - i))) & 1023 for i in range(NCHECK)]


def words_valid(vals):
    return polymod(list(CS) + list(vals), GENERATOR) == 1


def rs_correct(vals, limit):
    """Errors and erasures: syndromes, the erasure locator, Berlekamp-Massey
    started from it, Chien search over the written positions only, Forney.
    vals has None at an unreadable position. Returns (values, wrong positions,
    0-based) or None. The code word is 1 || cs || vals with the last symbol
    XOR 1, divisible by g, so the syndromes are its values at a^1..a^6; the
    word at 0-based position i is the coefficient of x^(n-1-i)."""
    n = len(vals)
    erased = [i for i, v in enumerate(vals) if v is None]
    f = len(erased)
    if f > NCHECK or f > limit:
        return None
    r = [1] + list(CS) + [0 if v is None else v for v in vals]
    r[-1] ^= 1
    m = len(r)
    syn = [0] * (NCHECK + 1)  # syn[j] = R(a^j), j = 1..6
    for j in range(1, NCHECK + 1):
        x, y = apow(j), 0
        for c in r:
            y = gmul(y, x) ^ c
        syn[j] = y
    gamma = [1]
    for i in erased:
        gamma = poly_mul(gamma, [1, apow(n - 1 - i)])
    lam, b, L = list(gamma), list(gamma), f
    for k in range(f + 1, NCHECK + 1):
        d = 0
        for i, c in enumerate(lam):
            if k - i >= 1:
                d ^= gmul(c, syn[k - i])
        xb = [0] + b
        if d == 0:
            b = xb
            continue
        t = [(lam[i] if i < len(lam) else 0) ^ (gmul(d, xb[i]) if i < len(xb) else 0)
             for i in range(max(len(lam), len(xb)))]
        if 2 * L <= k - 1 + f:
            b = [gmul(ginv(d), c) for c in lam]
            L = k + f - L
        else:
            b = xb
        lam = t
    while len(lam) > 1 and lam[-1] == 0:
        lam.pop()
    if len(lam) - 1 != L:
        return None
    e = L - f
    if e < 0 or 2 * e + f > NCHECK or 2 * e + f > limit:
        return None
    roots = [q for q in range(n) if poly_eval(lam, ginv(apow(q))) == 0]
    if len(roots) != L:
        return None  # a root off the written positions, or a repeated one
    omega = poly_mul(syn[1:], lam)[:NCHECK]
    dlam = [lam[i] if i % 2 == 1 else 0 for i in range(1, len(lam))]
    out = list(r)
    wrong = []
    for q in roots:
        xi = ginv(apow(q))
        den = poly_eval(dlam, xi)
        if den == 0:
            return None
        y = gmul(poly_eval(omega, xi), ginv(den))
        i = n - 1 - q
        out[m - 1 - q] ^= y
        if i not in erased:
            if y == 0:
                return None
            wrong.append(i)
    out[-1] ^= 1
    fixed = out[1 + len(CS):]
    if out[: 1 + len(CS)] != [1] + list(CS) or not words_valid(fixed):
        return None
    return fixed, sorted(wrong)


@functools.lru_cache(maxsize=None)
def wordlist():
    raw = open(WORDLIST_PATH, "rb").read()
    if hashlib.sha256(raw).hexdigest() != WORDLIST_SHA256:
        raise SystemExit("the word list's SHA-256 is not section 3.2's")
    words = raw.decode("ascii").split("\n")
    if words[-1] == "":
        words.pop()
    if len(words) != 1024 or len({w[:4] for w in words}) != 1024 or words[0] != "academic" or words[-1] != "zero":
        raise SystemExit("the word list is not 1024 words with unique first four letters")
    return words


def envelope_to_words(env):
    """Section 3.2, writing: the data words then the check words, as words."""
    if len(env) not in WORDS_SIZE.values():
        raise WriterRefuses("no words form at %d bytes" % len(env))
    nbits = 8 * len(env) - 5
    big = int.from_bytes(env, "big")
    if big >> nbits != 0b11111:
        raise WriterRefuses("no marker")
    nd = -(-nbits // 10)
    v = (big & ((1 << nbits) - 1)) << (10 * nd - nbits)
    data = [(v >> (10 * (nd - 1 - i))) & 1023 for i in range(nd)]
    return [wordlist()[x] for x in data + check_words(data)]


def name_word(s):
    """Section 3.2, reading, step 1: the word's value, or None (unreadable)."""
    if s == "?" or len(s) < 4 or not all("a" <= ch <= "z" or "A" <= ch <= "Z" for ch in s):
        return None
    low = s.lower()
    for i, w in enumerate(wordlist()):
        if w[:4] == low[:4]:
            return i if w.startswith(low) else None
    return None


def read_words(inputs, limit=RULE_LIMIT, decoder=None):
    """Section 3.2, reading. Returns ("not_aqrv", why), ("no_check",) or
    ("words", envelope, unreadable, wrong, corrected, words); positions from 1."""
    decoder = decoder or rs_correct
    if len(inputs) not in WORDS_SIZE:
        return ("not_aqrv", "count")
    n, size = len(inputs), WORDS_SIZE[len(inputs)]
    vals = [name_word(s) for s in inputs]
    unread = [i for i, v in enumerate(vals) if v is None]
    wrong = []
    if unread or not words_valid(vals):
        got = decoder(vals, limit)
        if got is None:
            return ("no_check",)
        vals, wrong = got
    wl = wordlist()
    corrected = [{"position": i + 1, "input": inputs[i], "word": wl[vals[i]]} for i in sorted(unread + wrong)]
    nd = n - NCHECK
    nbits = 8 * size - 5
    v = functools.reduce(lambda a, x: (a << 10) | x, vals[:nd], 0)
    spare = 10 * nd - nbits
    env = ((0b11111 << nbits) | (v >> spare)).to_bytes(size, "big")
    bad = "unused" if v & ((1 << spare) - 1) else "step" if env[0] & 7 not in STEP_KIB else None
    if bad:
        # step 5: after a correction in step 4 either means the words do not check
        return ("no_check",) if corrected else ("not_aqrv", bad)
    return ("words", env, [i + 1 for i in unread], [i + 1 for i in wrong], corrected, [wl[x] for x in vals])


# ---------------------------------------------------------------- words from text (section 3.2)

MAX_TEXT_BYTES, MAX_CUTS, MAX_READINGS, MAX_POSITIONS = 16384, 1024, 1024, 56
MARK_RANGES = [(0x0300, 0x036F), (0x1AB0, 0x1AFF), (0x1DC0, 0x1DFF), (0x20D0, 0x20FF), (0xFE20, 0xFE2F)]


def is_mark(ch):
    return any(a <= ord(ch) <= b for a, b in MARK_RANGES)


def is_letter(ch):
    """Unicode's Alphabetic property, which the standard library lacks:
    Alphabetic is Lu, Ll, Lt, Lm, Lo, Nl and Other_Alphabetic. This takes the
    general categories and leaves out Other_Alphabetic, whose characters are
    all of category Mn, Mc or So; alphabetic_unsure() names any character
    where the two could differ, and the run refuses a text holding one."""
    return unicodedata.category(ch) in ("Lu", "Ll", "Lt", "Lm", "Lo", "Nl")


def alphabetic_unsure(text):
    return sorted({"U+%04X" % ord(ch) for ch in text
                   if unicodedata.category(ch) in ("Mn", "Mc", "Me", "So") and not is_mark(ch)})


def join_hyphens(text):
    """Rule 2: a hyphen at a line break joins, the text read once from the start."""
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "-" and i > 0 and is_letter(text[i - 1]):
            j = i + 1
            while j < n and text[j] in " \t":
                j += 1
            if text.startswith("\r\n", j):
                j += 2
            elif j < n and text[j] == "\n":
                j += 1
            else:
                j = -1
            if j >= 0:
                while j < n and text[j] in " \t":
                    j += 1
                if j < n and is_letter(text[j]):
                    i = j
                    continue
        out.append(ch)
        i += 1
    return "".join(out)


def text_runs(text):
    """Rule 3: the runs, each with the separators directly before it."""
    runs, seps, i, n = [], [], 0, len(text)
    sep = []
    while i < n:
        ch = text[i]
        if ch == "?" or is_letter(ch) or is_mark(ch):
            q = ch == "?"
            j = i
            while j < n and ((text[j] == "?") if q else (is_letter(text[j]) or is_mark(text[j]))):
                j += 1
            runs.append(text[i:j])
            seps.append("".join(sep))
            sep = []
            i = j
        else:
            sep.append(ch)
            i += 1
    return runs, seps


def order_runs(runs, seps):
    """Rule 4: numbers 1 to n, each once, set the order."""
    nums = []
    for sp in seps:
        found = re.findall(r"[0-9]+", sp)
        if not found:
            return runs
        nums.append(int(found[-1]))
    if sorted(nums) != list(range(1, len(runs) + 1)):
        return runs
    return [r for _, r in sorted(zip(nums, runs))]


def run_cuts(run):
    """Rule 5: the run's cuts, longest first piece first, or "too_many"."""
    if run[0] == "?" or not all("a" <= ch <= "z" or "A" <= ch <= "Z" for ch in run):
        return [[run]]  # one unreadable position
    n = len(run)
    count = [0] * (n + 1)  # cuts of run[i:], capped above MAX_CUTS
    count[n] = 1
    for i in range(n - 1, -1, -1):
        count[i] = min(MAX_CUTS + 1, sum(count[i + k] for k in range(4, 9)
                                          if i + k <= n and name_word(run[i:i + k]) is not None))
    if count[0] > MAX_CUTS:
        return "too_many"
    if count[0] == 0:
        return [[run]]  # one position, unreadable by step 1
    cuts = []

    def walk(i, acc):
        if i == n:
            cuts.append(list(acc))
            return
        for k in range(8, 3, -1):
            if i + k <= n and count[i + k] and name_word(run[i:i + k]) is not None:
                walk(i + k, acc + [run[i:i + k]])

    walk(0, [])
    return cuts


def read_text_words(text, decoder=None):
    """Section 3.2, reading words from text. Returns ("too_many",),
    ("ambiguous",), or read_words' answer for the chosen reading."""
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        return ("too_many",)
    runs, seps = text_runs(join_hyphens(text))
    runs = order_runs(runs, seps)
    all_cuts = []
    for r in runs:
        c = run_cuts(r)
        if c == "too_many":
            return ("too_many",)
        all_cuts.append(c)
    # rule 6: readings of at most 56 positions, counted before they are made
    least = [0] * (len(all_cuts) + 1)
    for i in range(len(all_cuts) - 1, -1, -1):
        least[i] = least[i + 1] + min(len(c) for c in all_cuts[i])
    ways = [{0: 1}]
    for cuts in all_cuts:
        nxt = {}
        for k, w in ways[-1].items():
            for c in cuts:
                if k + len(c) <= MAX_POSITIONS:
                    nxt[k + len(c)] = min(MAX_READINGS + 1, nxt.get(k + len(c), 0) + w)
        ways.append(nxt)
    if sum(ways[-1].values()) > MAX_READINGS:
        return ("too_many",)
    readings = []

    def walk(i, acc):
        if i == len(all_cuts):
            readings.append(list(acc))
            return
        for c in all_cuts[i]:
            if len(acc) + len(c) + least[i + 1] <= MAX_POSITIONS:
                walk(i + 1, acc + c)

    walk(0, [])
    # rule 7
    kept = [r for r in readings if len(r) in WORDS_SIZE]
    if not kept:
        first = readings[0] if readings else [p for c in all_cuts for p in c[0]]
        return ("not_aqrv", "count", len(first))
    as_is = [r for r in kept if all(name_word(s) is not None for s in r) and words_valid([name_word(s) for s in r])]
    answers = [read_words(r, decoder=decoder) for r in (as_is or kept)]
    # rule 8
    envs = [a for a in answers if a[0] == "words"]
    if not envs:
        return ("not_aqrv", "step 5") if any(a[0] == "not_aqrv" for a in answers) else ("no_check",)
    if len({a[1] for a in envs}) == 1 and not any(a[0] == "not_aqrv" for a in answers):
        return min(envs, key=lambda a: len(a[4]))  # min keeps the first of the fewest
    return ("ambiguous",)


def reedsolo_decoder():
    """reedsolo's errors-and-erasures decoder as a drop-in for rs_correct, or
    None if reedsolo is not installed. The mapping is checked by encoding."""
    try:
        import reedsolo
    except ImportError:
        return None, "reedsolo not available", None
    codec = reedsolo.RSCodec(NCHECK, nsize=1023, c_exp=10, prim=GF_MOD, generator=2, fcr=1)
    import random

    rnd = random.Random(2)
    for n in WORDS_SIZE:
        for _ in range(20):
            data = [rnd.randrange(1024) for _ in range(n - NCHECK)]
            enc = list(codec.encode([1] + list(CS) + data))
            enc[-1] ^= 1
            if enc[1 + len(CS) + len(data):] != check_words(data):
                return None, "reedsolo", "reedsolo's code is not the words' code under the mapping"

    def decode(vals, limit):
        decode.calls += 1
        pre = 1 + len(CS)
        r = [1] + list(CS) + [0 if v is None else v for v in vals]
        r[-1] ^= 1
        erased = [pre + i for i, v in enumerate(vals) if v is None]
        try:
            _, full, _ = codec.decode(r, erase_pos=erased)
        except reedsolo.ReedSolomonError:
            return None
        full = list(full)
        if len(full) != len(r) or full[:pre] != [1] + list(CS):
            return None
        full[-1] ^= 1
        fixed = full[pre:]
        wrong = [i for i, v in enumerate(vals) if v is not None and v != fixed[i]]
        f = len(erased)
        if 2 * len(wrong) + f > limit or not words_valid(fixed):
            return None
        return fixed, wrong

    decode.calls = 0
    return decode, "reedsolo", None


# ---------------------------------------------------------------- PNG and QR


def png_modules(path):
    """Reads the picture with no image library; returns (chunk names, rows of
    modules without the quiet zone, 1 is dark)."""
    data = open(path, "rb").read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos, names, idat, ihdr = 8, [], b"", None
    while pos < len(data):
        ln, name = struct.unpack(">I4s", data[pos : pos + 8])
        body = data[pos + 8 : pos + 8 + ln]
        names.append(name.decode())
        if name == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", body)
        elif name == b"IDAT":
            idat += body
        pos += 12 + ln
    w, h, depth, ctype, _, _, interlace = ihdr
    if (depth, ctype, interlace) != (1, 0, 0):
        raise ValueError("not 1-bit greyscale without interlace")
    raw = zlib.decompress(idat)
    stride = (w + 7) // 8
    rows, prev = [], bytes(stride)
    for y in range(h):
        f = raw[y * (stride + 1)]
        line = bytearray(raw[y * (stride + 1) + 1 : (y + 1) * (stride + 1)])
        if f == 0:
            pass
        elif f == 1:
            for i in range(1, stride):
                line[i] = (line[i] + line[i - 1]) & 255
        elif f == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 255
        elif f == 3:
            for i in range(stride):
                a = line[i - 1] if i else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 255
        elif f == 4:
            for i in range(stride):
                a = line[i - 1] if i else 0
                b, c = prev[i], prev[i - 1] if i else 0
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 255
        else:
            raise ValueError("filter")
        prev = bytes(line)
        rows.append(prev)
    pix = [[(rows[y][x // 8] >> (7 - x % 8)) & 1 for x in range(w)] for y in range(h)]
    return names, pix


def matrix_from_png(path, modules):
    names, pix = png_modules(path)
    scale, quiet = 8, 4
    total = (modules + 2 * quiet) * scale
    if len(pix) != total or len(pix[0]) != total:
        raise ValueError("size %dx%d, expected %d" % (len(pix[0]), len(pix), total))
    rows = []
    for my in range(-quiet, modules + quiet):
        row = ""
        for mx in range(-quiet, modules + quiet):
            cell = {pix[(my + quiet) * scale + dy][(mx + quiet) * scale + dx] for dy in range(scale) for dx in range(scale)}
            if len(cell) != 1:
                raise ValueError("a module is not one colour")
            row += "1" if cell == {0} else "0"  # 0 is black in greyscale
        rows.append(row)
    inner = [r[quiet : quiet + modules] for r in rows[quiet : quiet + modules]]
    quiet_ok = all("1" not in r for r in rows[:quiet] + rows[-quiet:]) and all("1" not in r[:quiet] + r[-quiet:] for r in rows)
    return names, inner, quiet_ok


def qr_checks(data, fails):
    notes = []
    for q in data["qr"]:
        path = os.path.join(HERE, q["png"])
        try:
            names, inner, quiet_ok = matrix_from_png(path, q["modules"])
        except Exception as e:  # noqa: BLE001
            fails.append("qr %s: %s" % (q["png"], e))
            continue
        if inner != q["matrix"]:
            fails.append("qr %s: the picture's modules differ from the matrix in the JSON" % q["png"])
        if not quiet_ok:
            fails.append("qr %s: the quiet zone is not light" % q["png"])
        if sorted(names) != sorted(["IHDR", "IDAT", "IEND"]):
            fails.append("qr %s: chunks %s" % (q["png"], names))
        if hashlib.sha256(open(path, "rb").read()).hexdigest() != q["png_sha256"]:
            fails.append("qr %s: sha256 differs from the JSON" % q["png"])
        want = bytes.fromhex(q["envelope"])
        if "text" in q:
            if text_to_envelope(q["text"]) != want or envelope_to_text(want) != q["text"]:
                fails.append("qr %s: the text is not the envelope's text form" % q["png"])
            want = q["text"].encode("ascii")
        notes.append(decode_qr(path, want, q["png"], fails))
    return notes


def decode_qr(path, want, label, fails):
    out = []
    try:
        import zxingcpp
        from PIL import Image

        found = zxingcpp.read_barcodes(Image.open(path).convert("L"), formats=zxingcpp.BarcodeFormat.QRCode)
        if len(found) != 1:
            fails.append("qr %s: zxing-cpp finds %d symbols" % (label, len(found)))
        elif bytes(found[0].bytes) != want:
            fails.append("qr %s: zxing-cpp reads other bytes" % label)
        else:
            out.append("zxing-cpp")
    except ImportError as e:
        out.append("zxing-cpp not available (%s)" % e)
    try:
        run = subprocess.run(
            ["zbarimg", "--raw", "-q", "-Sdisable", "-Sqrcode.enable", "-Sbinary", path],
            capture_output=True, timeout=60,
        )
        if run.returncode != 0:
            fails.append("qr %s: zbarimg exits %d" % (label, run.returncode))
        elif run.stdout != want:
            fails.append("qr %s: zbar reads other bytes (%d)" % (label, len(run.stdout)))
        else:
            out.append("zbar")
    except FileNotFoundError:
        out.append("zbarimg not available")
    return "%s: %s" % (label, ", ".join(out))


# ---------------------------------------------------------------- the run

RULE_WORDS = {
    "size": "reserved", "room": "over the", "threshold": "neither 0 nor 2 to 9",
    "threshold-index": "not s", "len": "len is", "utf8": "not UTF-8",
}


def kind_in(text):
    m = re.search(r"kind (0x[0-9A-Fa-f]{2})", text)
    return int(m.group(1), 16) if m else None


def main():
    fails = []
    if not chacha20_self_test():
        print("ChaCha20 does not give RFC 8439 section 2.4.2")
        return 1
    bad = words_self_test()
    if bad:
        for b in bad:
            print(b)
        return 1
    data = json.load(open(os.path.join(HERE, "aqrv.json")))
    cases = data["cases"]
    pw_ = data["parameters"].get("words", {})
    if pw_ and ([int(x, 16) for x in pw_["generator"]] != GENERATOR or pw_["customization_string"].encode() != CS
                or pw_["word_list_sha256"] != WORDLIST_SHA256
                or {s["words"]: s["bytes"] for s in pw_["sizes"]} != WORDS_SIZE):
        fails.append("parameters.words: the generator, customization string, list or sizes differ from section 3.2")
    opened = refused = unrec = sealed = values_n = words_n = 0
    for case in cases:
        name, exp = case["name"], case["expect"]
        env = bytes.fromhex(case["envelope"])
        ans, vals = read(env, case.get("passphrase") or case["kef"]["passphrase"])
        out = exp["outcome"]
        if "words" in case:
            words_n += 1
            try:
                if envelope_to_words(env) != case["words"]:
                    fails.append("%s: the words written differ" % name)
            except WriterRefuses as e:
                fails.append("%s: the words writer refuses: %s" % (name, e))
            back = read_words(case["words"])
            if back[0] != "words" or back[1] != env or back[4]:
                fails.append("%s: the words do not read back as the envelope: %s" % (name, back[:2]))
        elif len(env) == 37 or (len(env) in (53, 62) and out == "opens"):
            fails.append("%s: no words given" % name)
        if out == "not_recognised":
            unrec += 1
            if ans[0] != "not_recognised":
                fails.append("%s: expected not recognised, got %s" % (name, ans[0]))
            continue
        if out == "does_not_open":
            refused += 1
            if "no kind's tag" in exp["why"]:
                if ans[0] != "no_match":
                    fails.append("%s: expected no tag to match, got %s" % (name, ans))
            else:
                k = kind_in(exp["why"])
                if ans[0] != "layout" or ans[1] != k:
                    fails.append("%s: expected a layout refusal of kind 0x%02X, got %s" % (name, k or 0, ans))
                elif RULE_WORDS[ans[2]] not in exp["reason"]:
                    fails.append("%s: refused by rule %r, the case says %r" % (name, ans[2], exp["reason"]))
        elif out == "opens":
            opened += 1
            if ans[0] != "opens":
                fails.append("%s: expected to open, got %s" % (name, ans))
            else:
                if ans[1] != int(exp["kind"], 16):
                    fails.append("%s: kind 0x%02X, expected %s" % (name, ans[1], exp["kind"]))
                if ans[2] != exp["item"]:
                    fails.append("%s: item %s, expected %s" % (name, ans[2], exp["item"]))
        # the intermediate values the case gives
        for key, want in case.get("values", {}).items():
            if key not in vals:
                continue
            got = vals[key]
            if key == "tags":
                for k, w in want.items():
                    values_n += 1
                    if got.get(k) != w:
                        fails.append("%s: tags[%s] %s, expected %s" % (name, k, got.get(k), w))
            elif key == "hmac_message":
                values_n += 1
                if got[kind_of(case)].hex() != want:
                    fails.append("%s: hmac_message differs" % name)
            else:
                values_n += 1
                if got != want:
                    fails.append("%s: %s %s, expected %s" % (name, key, got, want))
        if "header" in case and case["header"] != "0x%02X" % env[0]:
            fails.append("%s: header" % name)
        if "item_bytes" in case and "P" in vals and ans[0] in ("opens", "layout"):
            ib = case["item_bytes"]
            if case["kind"] == "0x30":
                ib = ib[:-2]  # the last byte's low bits are padding bits
            if not vals["P"].startswith(ib):
                fails.append("%s: P does not start with item_bytes" % name)
        # sealing
        if out == "opens":
            sealed += 1
            fill = int(case["last_byte_fill"], 16) if "last_byte_fill" in case else 0
            try:
                got = seal(case["passphrase"], case["step"], case["size"], int(case["kind"], 16),
                           exp["item"], bytes.fromhex(case["salt"]), bytes.fromhex(case["padding"]), fill)
            except WriterRefuses as e:
                fails.append("%s: the writer refuses: %s" % (name, e))
                continue
            if got != env:
                fails.append("%s: sealed envelope differs" % name)
    # what a writer refuses
    for r in data["writer_refuses"]:
        if "size" in r:
            try:
                seal("p", 0, r["size"], int(r["kind"], 16), r["item"], bytes(SALT[r["size"]]), b"")
                fails.append("writer takes %s at %d bytes (%s)" % (r["kind"], r["size"], r["reason"]))
            except WriterRefuses:
                pass
            continue
        try:
            codex32_item(r["string"], 0)
            fails.append("writer takes %r (%s)" % (r["string"], r["reason"]))
        except WriterRefuses:
            pass
    for what, call in (
        ("empty passphrase", lambda: seal("", 0, 53, 0x41, {"text": "x"}, bytes(16), bytes(30))),
        ("empty note", lambda: item_bytes_for(0x41, {"text": ""}, 0)),
        ("note over the room at 53", lambda: seal("p", 0, 53, 0x41, {"text": "x" * 32}, bytes(16), b"")),
        ("37 bytes of codex32 at 53", lambda: seal("p", 0, 53, 0x30, {"string": "ms1" + "q" * 71}, bytes(16), b"")),
        ("a raw key at 32", lambda: seal("p", 0, 32, 0x50, {"hex": "00" * 32}, bytes(11), b"")),
        ("a 16-byte salt at 32", lambda: seal("p", 0, 32, 0x10, {"hex": "00" * 16}, bytes(16), b"")),
    ):
        try:
            call()
            fails.append("writer takes: %s" % what)
        except WriterRefuses:
            pass
    # the 32-byte size's text form
    texts = 0
    for tc in data.get("qr_text", []):
        texts += 1
        name, exp = tc["name"], tc["expect"]
        env = text_to_envelope(tc["text"])
        if exp["outcome"] == "not_recognised":
            if env is not None and recognised(env):
                fails.append("%s: the text is recognised" % name)
            continue
        if env is None or env.hex() != exp["envelope"] or envelope_to_text(env) != tc["text"]:
            fails.append("%s: the text does not decode to the envelope" % name)
            continue
        ans, _ = read(env, tc["passphrase"])
        if ans[0] != "opens" or ans[1] != int(exp["kind"], 16) or ans[2] != exp["item"]:
            fails.append("%s: expected to open, got %s" % (name, ans))
    # the lists of words
    outside, outside_note, outside_bad = reedsolo_decoder()
    if outside_bad:
        fails.append(outside_bad)
    for c in cases:
        if len(bytes.fromhex(c["envelope"])) == 32:
            if "words" in c:
                fails.append("%s: a 32-byte case carries words" % c["name"])
            try:
                envelope_to_words(bytes.fromhex(c["envelope"]))
                fails.append("%s: the words writer takes a 32-byte envelope" % c["name"])
            except WriterRefuses:
                pass
    for w in data.get("words", []):
        name, exp = w["name"], w["expect"]
        got = read_words(w["input"])
        out = exp["outcome"]
        if out == "not_aqrv_words":
            why = {"count": "words:", "unused": "unused bit", "step": "step"}
            if got[0] != "not_aqrv":
                fails.append("%s: expected not AQRV words, got %s" % (name, got[0]))
            elif why[got[1]] not in exp["reason"]:
                fails.append("%s: not AQRV words by %r, the entry says %r" % (name, got[1], exp["reason"]))
            elif got[1] != "count" and not ("?" not in w["input"] and words_valid([name_word(s) for s in w["input"]])):
                fails.append("%s: the words do not check as given" % name)
        elif out == "words_do_not_check":
            if got[0] != "no_check":
                fails.append("%s: expected the words not to check, got %s" % (name, got[0]))
            # whether the decoder alone, allowed 2e + f <= 6, finds valid words (step 5 aside)
            named = [name_word(s) for s in w["input"]]
            wide = len(named) in WORDS_SIZE and rs_correct(named, NCHECK) is not None
            if wide != exp["decodes_without_the_rule"]:
                fails.append("%s: decodes with 2e + f <= 6: %s, expected %s"
                             % (name, wide, exp["decodes_without_the_rule"]))
        elif out == "opens":
            if got[0] != "words":
                fails.append("%s: expected words that open, got %s" % (name, got))
            else:
                _, env, unread, wrong, corrected, words = got
                for key, mine in (("unreadable", unread), ("wrong", wrong), ("corrected", corrected),
                                  ("words", words), ("envelope", env.hex())):
                    if mine != exp[key]:
                        fails.append("%s: %s %s, expected %s" % (name, key, mine, exp[key]))
                ans, _ = read(env, w["passphrase"])
                if ans[0] != "opens" or ans[1] != int(exp["kind"], 16) or ans[2] != exp["item"]:
                    fails.append("%s: expected to open as %s, got %s" % (name, exp["kind"], ans))
        else:
            fails.append("%s: outcome %s" % (name, out))
        if outside and len(w["input"]) in WORDS_SIZE:
            theirs = read_words(w["input"], decoder=outside)
            if theirs != got:
                fails.append("%s: reedsolo gives %s, our decoder %s" % (name, theirs[:1], got[:1]))
            if out == "words_do_not_check":
                named = [name_word(s) for s in w["input"]]
                if (outside(named, NCHECK) is None) != (rs_correct(named, NCHECK) is None):
                    fails.append("%s: with 2e + f <= 6, reedsolo and our decoder differ" % name)
    # the words as text
    text_n = 0
    for w in data.get("words_text", []):
        text_n += 1
        name, exp = w["name"], w["expect"]
        unsure = alphabetic_unsure(w["text"])
        if unsure:
            fails.append("%s: holds %s, where the Alphabetic property is not known here" % (name, unsure))
            continue
        got = read_text_words(w["text"])
        out = exp["outcome"]
        mine = {"words": "opens", "no_check": "words_do_not_check", "not_aqrv": "not_aqrv_words",
                "ambiguous": "ambiguous", "too_many": "too_many"}[got[0]]
        if mine != out:
            fails.append("%s: %s, expected %s (%s)" % (name, mine, out, exp.get("reason", "")))
        elif out == "opens":
            _, env, unread, wrong, corrected, words = got
            for key, m in (("unreadable", unread), ("wrong", wrong), ("corrected", corrected),
                           ("words", words), ("envelope", env.hex())):
                if m != exp[key]:
                    fails.append("%s: %s %s, expected %s" % (name, key, m, exp[key]))
            ans, _ = read(env, w["passphrase"])
            if ans[0] != "opens" or ans[1] != int(exp["kind"], 16) or ans[2] != exp["item"]:
                fails.append("%s: expected to open as %s, got %s" % (name, exp["kind"], ans))
        if outside and read_text_words(w["text"], decoder=outside) != got:
            fails.append("%s: through reedsolo the text reads otherwise" % name)
    qr_notes = [] if "--no-qr" in sys.argv else qr_checks(data, fails)
    print("%d cases: %d open, %d do not open, %d not recognised; %d sealed again; %d values compared; "
          "%d text forms; %d cases' words; %d lists of words (%s); %d texts of words; %d disagreements"
          % (len(cases), opened, refused, unrec, sealed, values_n, texts, words_n, len(data.get("words", [])),
             "%d decodings repeated by reedsolo" % outside.calls if outside else outside_note, text_n, len(fails)))
    for n in qr_notes:
        print("qr " + n)
    for f in fails:
        print("DISAGREES " + f)
    return 1 if fails else 0


def kind_of(case):
    return int(case["kind"], 16)


if __name__ == "__main__":
    sys.exit(main())
