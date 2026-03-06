"""PhantomRecon — John the Ripper Expert Edition
================================================
Advanced password hash cracking engine with:
  • 35+ hash formats
  • 10+ attack modes: dictionary, rules, single, incremental, mask,
    Markov, PRINCE, combinator, hybrid, keyboard, association, pattern
  • JtR-compatible rule string parser (150+ built-in rules)
  • Markov chain generation (trainable + built-in frequency tables)
  • PRINCE attack (element-chain combination from wordlist)
  • Combinator attack (two-wordlist cross-product)
  • Hybrid attacks (wordlist+mask, mask+wordlist)
  • Keyboard walk patterns (QWERTY, AZERTY, Dvorak, numeric)
  • Session save / resume (pickle-based)
  • Real-time H/s statistics with ETA
  • Multiprocessing for CPU-bound hash operations
  • Smart candidate prioritisation (frequency-ordered charsets)
  • Pot-file persistence with deduplication and per-format stats
"""

import base64
import hashlib
import hmac as _hmac_mod
import itertools
import json
import multiprocessing
import os
import pickle
import random
import re
import string
import struct
import sys
import threading
import time
import zlib
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Hash format definitions  (35 formats)
# ---------------------------------------------------------------------------

class HashFormat(str, Enum):
    MD5           = "md5"
    SHA1          = "sha1"
    SHA224        = "sha224"
    SHA256        = "sha256"
    SHA384        = "sha384"
    SHA512        = "sha512"
    SHA3_256      = "sha3_256"
    SHA3_512      = "sha3_512"
    MD4           = "md4"
    NTLM          = "ntlm"
    LM            = "lm"
    MYSQL323      = "mysql323"
    MYSQL41       = "mysql41"
    MD5CRYPT      = "md5crypt"
    SHA256CRYPT   = "sha256crypt"
    SHA512CRYPT   = "sha512crypt"
    BCRYPT        = "bcrypt"
    BLAKE2B       = "blake2b"
    RIPEMD160     = "ripemd160"
    DOUBLE_MD5    = "double_md5"
    SHA1_UPPER    = "sha1_upper"
    WORDPRESS     = "wordpress"
    DJANGO_PBKDF2 = "django_pbkdf2"
    ORACLE11G     = "oracle11g"
    MD5_SALT      = "md5_salt"
    SHA1_SALT     = "sha1_salt"
    SHA256_SALT   = "sha256_salt"
    HMAC_MD5      = "hmac_md5"
    HMAC_SHA1     = "hmac_sha1"
    HMAC_SHA256   = "hmac_sha256"
    CRC32         = "crc32"
    CISCO_PIX     = "cisco_pix"
    HALF_MD5      = "half_md5"
    WHIRLPOOL     = "whirlpool"
    UNKNOWN       = "unknown"


FORMAT_ALIASES: dict[str, "HashFormat"] = {
    "md5":           HashFormat.MD5,
    "sha1":          HashFormat.SHA1,
    "sha224":        HashFormat.SHA224,
    "sha256":        HashFormat.SHA256,
    "sha384":        HashFormat.SHA384,
    "sha512":        HashFormat.SHA512,
    "sha3-256":      HashFormat.SHA3_256,
    "sha3_256":      HashFormat.SHA3_256,
    "sha3-512":      HashFormat.SHA3_512,
    "sha3_512":      HashFormat.SHA3_512,
    "md4":           HashFormat.MD4,
    "ntlm":          HashFormat.NTLM,
    "nt":            HashFormat.NTLM,
    "lm":            HashFormat.LM,
    "mysql":         HashFormat.MYSQL323,
    "mysql-old":     HashFormat.MYSQL323,
    "mysql323":      HashFormat.MYSQL323,
    "mysql41":       HashFormat.MYSQL41,
    "mysql-sha1":    HashFormat.MYSQL41,
    "md5crypt":      HashFormat.MD5CRYPT,
    "md5-crypt":     HashFormat.MD5CRYPT,
    "sha256crypt":   HashFormat.SHA256CRYPT,
    "sha512crypt":   HashFormat.SHA512CRYPT,
    "bcrypt":        HashFormat.BCRYPT,
    "blake2b":       HashFormat.BLAKE2B,
    "ripemd160":     HashFormat.RIPEMD160,
    "double_md5":    HashFormat.DOUBLE_MD5,
    "wordpress":     HashFormat.WORDPRESS,
    "phpass":        HashFormat.WORDPRESS,
    "django":        HashFormat.DJANGO_PBKDF2,
    "django_pbkdf2": HashFormat.DJANGO_PBKDF2,
    "oracle11g":     HashFormat.ORACLE11G,
    "oracle":        HashFormat.ORACLE11G,
    "md5_salt":      HashFormat.MD5_SALT,
    "sha1_salt":     HashFormat.SHA1_SALT,
    "sha256_salt":   HashFormat.SHA256_SALT,
    "hmac_md5":      HashFormat.HMAC_MD5,
    "hmac_sha1":     HashFormat.HMAC_SHA1,
    "hmac_sha256":   HashFormat.HMAC_SHA256,
    "crc32":         HashFormat.CRC32,
    "cisco_pix":     HashFormat.CISCO_PIX,
    "half_md5":      HashFormat.HALF_MD5,
    "whirlpool":     HashFormat.WHIRLPOOL,
}


# ---------------------------------------------------------------------------
# Hash identification (improved — handles 35 formats)
# ---------------------------------------------------------------------------

class HashIdentifier:
    _HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

    @classmethod
    def identify(cls, h: str) -> list[HashFormat]:
        h = h.strip()

        if h.startswith(('$2b$', '$2a$', '$2y$')):
            return [HashFormat.BCRYPT]
        if h.startswith('$6$'):
            return [HashFormat.SHA512CRYPT]
        if h.startswith('$5$'):
            return [HashFormat.SHA256CRYPT]
        if h.startswith('$1$'):
            return [HashFormat.MD5CRYPT]
        if h.startswith(('$P$', '$H$')):
            return [HashFormat.WORDPRESS]
        if h.startswith('pbkdf2_sha256$'):
            return [HashFormat.DJANGO_PBKDF2]
        if h.startswith('S:') and len(h) == 62:
            return [HashFormat.ORACLE11G]
        if h.startswith('*') and len(h) == 41 and cls._HEX_RE.match(h[1:]):
            return [HashFormat.MYSQL41]

        if ':' in h:
            left, _, right = h.rpartition(':')
            if cls._HEX_RE.match(left):
                if len(left) == 32:
                    return [HashFormat.MD5_SALT, HashFormat.HMAC_MD5]
                if len(left) == 40:
                    return [HashFormat.SHA1_SALT, HashFormat.HMAC_SHA1]
                if len(left) == 64:
                    return [HashFormat.SHA256_SALT, HashFormat.HMAC_SHA256]
            h_check = right if cls._HEX_RE.match(right) else left
            if cls._HEX_RE.match(h_check):
                h = h_check

        if not cls._HEX_RE.match(h):
            return [HashFormat.UNKNOWN]

        length = len(h)
        length_map: dict[int, list[HashFormat]] = {
            8:   [HashFormat.CRC32],
            16:  [HashFormat.MYSQL323, HashFormat.HALF_MD5],
            32:  [HashFormat.MD5, HashFormat.NTLM, HashFormat.MD4, HashFormat.DOUBLE_MD5],
            40:  [HashFormat.SHA1, HashFormat.SHA1_UPPER, HashFormat.RIPEMD160],
            48:  [HashFormat.CISCO_PIX],
            56:  [HashFormat.SHA224],
            64:  [HashFormat.SHA256, HashFormat.SHA3_256, HashFormat.BLAKE2B],
            80:  [HashFormat.WHIRLPOOL],
            96:  [HashFormat.SHA384],
            128: [HashFormat.SHA512, HashFormat.SHA3_512, HashFormat.BLAKE2B],
        }
        return length_map.get(length, [HashFormat.UNKNOWN])

    @classmethod
    def identify_best(cls, h: str) -> HashFormat:
        results = cls.identify(h)
        return results[0] if results else HashFormat.UNKNOWN

    @classmethod
    def identify_all_candidates(cls, hashes: list[str]) -> HashFormat:
        counts: Counter = Counter()
        for h in hashes:
            for f in cls.identify(h):
                counts[f] += 1
        if counts:
            return counts.most_common(1)[0][0]
        return HashFormat.UNKNOWN


# ---------------------------------------------------------------------------
# Pure-Python hash implementations
# ---------------------------------------------------------------------------

def _md4(data: bytes) -> bytes:
    try:
        return hashlib.new('md4', data).digest()
    except ValueError:
        return _md4_pure(data)


def _md4_pure(msg: bytes) -> bytes:
    def _lrot(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z

    msg = bytearray(msg)
    bit_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', bit_len)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for i in range(0, len(msg), 64):
        X = list(struct.unpack('<16I', msg[i:i+64]))
        a, b, c, d = a0, b0, c0, d0
        for j in range(16):
            a = _lrot((a + F(b,c,d) + X[j]) & 0xFFFFFFFF, [3,7,11,19][j%4])
            a, b, c, d = d, a, b, c
        for j, s in zip([0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15], [3,5,9,13]*4):
            a = _lrot((a + G(b,c,d) + X[j] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        for j, s in zip([0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15], [3,9,11,15]*4):
            a = _lrot((a + H(b,c,d) + X[j] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        a0 = (a0 + a) & 0xFFFFFFFF; b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF; d0 = (d0 + d) & 0xFFFFFFFF
    return struct.pack('<4I', a0, b0, c0, d0)


def _mysql323(password: str) -> str:
    if not password:
        return '0000000000000000'
    nr, nr2, add = 1345345333, 0x12345671, 7
    for c in password:
        if c in (' ', '\t'):
            continue
        tmp = ord(c)
        nr  ^= (((nr & 63) + add) * tmp) + (nr << 8)
        nr  &= 0xFFFFFFFF
        nr2 += (nr2 << 8) ^ nr
        nr2 &= 0xFFFFFFFF
        add += tmp
    return f"{nr & 0x7FFFFFFF:08x}{nr2 & 0x7FFFFFFF:08x}"


def _mysql41(password: str) -> str:
    h1 = hashlib.sha1(password.encode('utf-8', errors='replace')).digest()
    return '*' + hashlib.sha1(h1).hexdigest().upper()


def _des_ecb(key7: bytes, data: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        k = bytearray(8)
        for i, b in enumerate(key7[:7].ljust(7, b'\x00')):
            pass
        raw = key7[:7].ljust(7, b'\x00')
        k[0] = raw[0] >> 1
        k[1] = ((raw[0] & 1) << 6) | (raw[1] >> 2)
        k[2] = ((raw[1] & 3) << 5) | (raw[2] >> 3)
        k[3] = ((raw[2] & 7) << 4) | (raw[3] >> 4)
        k[4] = ((raw[3] & 15)<< 3) | (raw[4] >> 5)
        k[5] = ((raw[4] & 31)<< 2) | (raw[5] >> 6)
        k[6] = ((raw[5] & 63)<< 1) | (raw[6] >> 7)
        k[7] = raw[6] & 0x7F
        key8 = bytes(b << 1 for b in k)
        c = Cipher(algorithms.TripleDES(key8 * 3), modes.ECB(), backend=default_backend())
        enc = c.encryptor()
        return enc.update(data) + enc.finalize()
    except Exception:
        return b'\x00' * 8


def _lm_hash(password: str) -> str:
    try:
        pwd = password.upper()[:14].encode('ascii', errors='replace').ljust(14, b'\x00')
        magic = b"KGS!@#$%"
        return (_des_ecb(pwd[:7], magic) + _des_ecb(pwd[7:], magic)).hex()
    except Exception:
        return ""


def _md5crypt(password: str, salt: str) -> str:
    pwd = password.encode('utf-8')
    slt = salt.encode('utf-8') if isinstance(salt, str) else salt
    def md5(*args):
        h = hashlib.md5()
        for a in args: h.update(a)
        return h.digest()
    digest_b = md5(pwd, slt, pwd)
    alt = bytearray()
    for i in range(0, len(pwd), 16):
        alt += digest_b[:min(len(pwd)-i, 16)]
    tmp = bytearray(pwd)
    for i in range(7, -1, -1):
        tmp += (digest_b if len(pwd) & (1 << i) else pwd)
    c = md5(bytes(tmp))
    for i in range(1000):
        dp = bytearray()
        dp += (pwd if i & 1 else c)
        if i % 3: dp += slt
        if i % 7: dp += pwd
        dp += (c if i & 1 else pwd)
        c = md5(bytes(dp))
    B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    def b64(b2, b1, b0, n):
        w = (b2 << 16) | (b1 << 8) | b0
        return ''.join(B64[(w >> (6*i)) & 0x3f] for i in range(n))
    result = (b64(c[0],c[6],c[12],4) + b64(c[1],c[7],c[13],4) +
              b64(c[2],c[8],c[14],4) + b64(c[3],c[9],c[15],4) +
              b64(c[4],c[10],c[5],4) + b64(0,0,c[11],2))
    return f"$1${slt.decode('utf-8',errors='replace')}${result}"


def _sha512crypt(password: str, salt: str) -> str:
    pwd = password.encode('utf-8')
    slt_raw = salt.encode('utf-8') if isinstance(salt, str) else salt
    rounds = 5000
    rounds_custom = False
    slt = slt_raw
    if slt_raw.startswith(b'rounds='):
        parts = slt_raw.split(b'$', 1)
        rounds = int(parts[0].split(b'=')[1])
        slt = parts[1] if len(parts) > 1 else b''
        rounds_custom = True
    def sha(*args):
        h = hashlib.sha512()
        for a in args: h.update(a)
        return h.digest()
    db = sha(pwd, slt, pwd)
    alt = bytearray()
    for i in range(0, len(pwd), 64): alt += db[:min(len(pwd)-i, 64)]
    tmp = bytearray(pwd)
    for i in range(7, -1, -1): tmp += (db if len(pwd) & (1 << i) else pwd)
    da = sha(bytes(tmp))
    dp = sha(pwd * len(pwd))
    p = bytearray()
    for i in range(0, len(pwd), 64): p += dp[:min(len(pwd)-i, 64)]
    p = bytes(p[:len(pwd)])
    ds = sha(slt * (16 + da[0]))
    s = bytearray()
    for i in range(0, len(slt), 64): s += ds[:min(len(slt)-i, 64)]
    s = bytes(s[:len(slt)])
    c = da
    for i in range(rounds):
        nc = bytearray()
        nc += (p if i & 1 else c)
        if i % 3: nc += s
        if i % 7: nc += p
        nc += (c if i & 1 else p)
        c = sha(bytes(nc))
    B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    def b64_from_24bit(b2, b1, b0, n):
        w = (b2 << 16) | (b1 << 8) | b0
        return ''.join(B64[(w >> (6*i)) & 0x3f] for i in range(n))
    result = (b64_from_24bit(c[0],c[21],c[42],4) + b64_from_24bit(c[22],c[43],c[1],4) +
              b64_from_24bit(c[44],c[2],c[23],4) + b64_from_24bit(c[3],c[24],c[45],4) +
              b64_from_24bit(c[25],c[46],c[4],4) + b64_from_24bit(c[47],c[5],c[26],4) +
              b64_from_24bit(c[6],c[27],c[48],4) + b64_from_24bit(c[28],c[49],c[7],4) +
              b64_from_24bit(c[50],c[8],c[29],4) + b64_from_24bit(c[9],c[30],c[51],4) +
              b64_from_24bit(c[31],c[52],c[10],4)+ b64_from_24bit(c[53],c[11],c[32],4)+
              b64_from_24bit(c[12],c[33],c[54],4)+ b64_from_24bit(c[34],c[55],c[13],4)+
              b64_from_24bit(c[56],c[14],c[35],4)+ b64_from_24bit(c[15],c[36],c[57],4)+
              b64_from_24bit(c[37],c[58],c[16],4)+ b64_from_24bit(c[59],c[17],c[38],4)+
              b64_from_24bit(c[18],c[39],c[60],4)+ b64_from_24bit(c[40],c[61],c[19],4)+
              b64_from_24bit(c[62],c[20],c[41],4)+ b64_from_24bit(0,c[63],c[21+21],3))
    prefix = f"$6${'rounds='+str(rounds)+'$' if rounds_custom else ''}"
    return f"{prefix}{slt.decode('utf-8',errors='replace')}${result}"


def _sha256crypt(password: str, salt: str) -> str:
    pwd = password.encode('utf-8')
    slt_raw = salt.encode('utf-8') if isinstance(salt, str) else salt
    rounds = 5000; rounds_custom = False; slt = slt_raw
    if slt_raw.startswith(b'rounds='):
        parts = slt_raw.split(b'$', 1)
        rounds = int(parts[0].split(b'=')[1])
        slt = parts[1] if len(parts) > 1 else b''
        rounds_custom = True
    def sha(*args):
        h = hashlib.sha256()
        for a in args: h.update(a)
        return h.digest()
    db = sha(pwd, slt, pwd)
    alt = bytearray()
    for i in range(0, len(pwd), 32): alt += db[:min(len(pwd)-i, 32)]
    tmp = bytearray(pwd)
    for i in range(7, -1, -1): tmp += (db if len(pwd) & (1 << i) else pwd)
    da = sha(bytes(tmp))
    dp = sha(pwd * len(pwd))
    p = bytearray()
    for i in range(0, len(pwd), 32): p += dp[:min(len(pwd)-i, 32)]
    p = bytes(p[:len(pwd)])
    ds = sha(slt * (16 + da[0]))
    s = bytearray()
    for i in range(0, len(slt), 32): s += ds[:min(len(slt)-i, 32)]
    s = bytes(s[:len(slt)])
    c = da
    for i in range(rounds):
        nc = bytearray()
        nc += (p if i & 1 else c)
        if i % 3: nc += s
        if i % 7: nc += p
        nc += (c if i & 1 else p)
        c = sha(bytes(nc))
    B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    def b64_from_24bit(b2, b1, b0, n):
        w = (b2 << 16) | (b1 << 8) | b0
        return ''.join(B64[(w >> (6*i)) & 0x3f] for i in range(n))
    result = (b64_from_24bit(c[0],c[10],c[20],4) + b64_from_24bit(c[21],c[1],c[11],4) +
              b64_from_24bit(c[12],c[22],c[2],4)  + b64_from_24bit(c[3],c[13],c[23],4) +
              b64_from_24bit(c[24],c[4],c[14],4)  + b64_from_24bit(c[15],c[25],c[5],4) +
              b64_from_24bit(c[6],c[16],c[26],4)  + b64_from_24bit(c[27],c[7],c[17],4) +
              b64_from_24bit(c[18],c[28],c[8],4)  + b64_from_24bit(c[9],c[19],c[29],4) +
              b64_from_24bit(0,c[31],c[30],3))
    prefix = f"$5${'rounds='+str(rounds)+'$' if rounds_custom else ''}"
    return f"{prefix}{slt.decode('utf-8',errors='replace')}${result}"


def _wordpress_hash(password: str, hash_str: str) -> str:
    ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    if not (hash_str.startswith('$P$') or hash_str.startswith('$H$')):
        return "__NO_MATCH__"
    count_log2 = ITOA64.find(hash_str[3])
    if count_log2 < 0: return "__NO_MATCH__"
    count = 1 << count_log2
    salt = hash_str[4:12].encode('utf-8', errors='replace')
    pwd  = password.encode('utf-8', errors='replace')
    h = hashlib.md5(salt + pwd).digest()
    for _ in range(count):
        h = hashlib.md5(h + pwd).digest()
    def encode64(inp, count):
        out = ''; i = 0
        while i < count:
            val = inp[i]; i += 1
            out += ITOA64[val & 0x3f]
            if i < count: val |= inp[i] << 8
            out += ITOA64[(val >> 6) & 0x3f]
            if i >= count: break
            i += 1
            if i < count: val |= inp[i] << 16
            out += ITOA64[(val >> 12) & 0x3f]
            if i >= count: break
            i += 1
            out += ITOA64[(val >> 18) & 0x3f]
        return out
    return hash_str[:12] + encode64(h, 16)


def _django_pbkdf2(password: str, hash_str: str) -> str:
    try:
        parts = hash_str.split('$')
        if len(parts) != 4: return "__NO_MATCH__"
        _, iters, salt, _ = parts
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), int(iters))
        return f"pbkdf2_sha256${iters}${salt}${base64.b64encode(dk).decode()}"
    except Exception:
        return "__NO_MATCH__"


def _oracle11g(password: str, hash_str: str) -> str:
    if not hash_str.startswith('S:'):
        return "__NO_MATCH__"
    try:
        salt_hex = hash_str[2+40:2+60]
        salt = bytes.fromhex(salt_hex)
        h = hashlib.sha1(password.upper().encode('utf-8') + salt).hexdigest().upper()
        return 'S:' + h + salt_hex.upper()
    except Exception:
        return "__NO_MATCH__"


def _cisco_pix(password: str) -> str:
    pwd = password.encode('ascii', errors='replace')[:16].ljust(16, b'\x00')
    return hashlib.md5(pwd).hexdigest()[:16]


def _bcrypt_hash(password: str, original_hash: str) -> str:
    try:
        import bcrypt as _bcrypt
        return original_hash if _bcrypt.checkpw(password.encode('utf-8'), original_hash.encode('utf-8')) else "__NO_MATCH__"
    except ImportError:
        raise RuntimeError("bcrypt format requires: pip install bcrypt")


def _extract_crypt_salt(hash_str: str, fmt: "HashFormat") -> str:
    parts = hash_str.split('$')
    if len(parts) >= 4:
        if parts[2].startswith('rounds=') and len(parts) >= 5:
            return f"rounds={parts[2].split('=')[1]}${parts[3]}"
        return parts[2]
    return hash_str


def _parse_salted(hash_str: str) -> tuple[str, str]:
    if ':' in hash_str:
        h, _, s = hash_str.rpartition(':')
        return h, s
    return hash_str, ''


# ---------------------------------------------------------------------------
# Unified hash computation / verification
# ---------------------------------------------------------------------------

def compute_hash(password: str, fmt: HashFormat, original_hash: str = "") -> str:
    b = password.encode('utf-8', errors='replace')
    if fmt == HashFormat.MD5:           return hashlib.md5(b).hexdigest()
    if fmt == HashFormat.HALF_MD5:      return hashlib.md5(b).hexdigest()[:16]
    if fmt == HashFormat.SHA1:          return hashlib.sha1(b).hexdigest()
    if fmt == HashFormat.SHA1_UPPER:    return hashlib.sha1(b).hexdigest().upper()
    if fmt == HashFormat.SHA224:        return hashlib.sha224(b).hexdigest()
    if fmt == HashFormat.SHA256:        return hashlib.sha256(b).hexdigest()
    if fmt == HashFormat.SHA384:        return hashlib.sha384(b).hexdigest()
    if fmt == HashFormat.SHA512:        return hashlib.sha512(b).hexdigest()
    if fmt == HashFormat.SHA3_256:      return hashlib.sha3_256(b).hexdigest()
    if fmt == HashFormat.SHA3_512:      return hashlib.sha3_512(b).hexdigest()
    if fmt == HashFormat.BLAKE2B:       return hashlib.blake2b(b).hexdigest()
    if fmt == HashFormat.MD4:           return _md4(b).hex()
    if fmt == HashFormat.NTLM:          return _md4(password.encode('utf-16-le')).hex()
    if fmt == HashFormat.LM:            return _lm_hash(password)
    if fmt == HashFormat.MYSQL323:      return _mysql323(password)
    if fmt == HashFormat.MYSQL41:       return _mysql41(password)
    if fmt == HashFormat.DOUBLE_MD5:    return hashlib.md5(hashlib.md5(b).hexdigest().encode()).hexdigest()
    if fmt == HashFormat.CRC32:         return f"{zlib.crc32(b) & 0xFFFFFFFF:08x}"
    if fmt == HashFormat.CISCO_PIX:     return _cisco_pix(password)
    if fmt == HashFormat.RIPEMD160:
        try:    return hashlib.new('ripemd160', b).hexdigest()
        except: return ""
    if fmt == HashFormat.WHIRLPOOL:
        try:    return hashlib.new('whirlpool', b).hexdigest()
        except: return ""
    if fmt in (HashFormat.MD5CRYPT, HashFormat.SHA256CRYPT, HashFormat.SHA512CRYPT):
        salt = _extract_crypt_salt(original_hash, fmt)
        if fmt == HashFormat.SHA512CRYPT:  return _sha512crypt(password, salt)
        if fmt == HashFormat.SHA256CRYPT:  return _sha256crypt(password, salt)
        return _md5crypt(password, salt)
    if fmt == HashFormat.BCRYPT:        return _bcrypt_hash(password, original_hash)
    if fmt == HashFormat.WORDPRESS:     return _wordpress_hash(password, original_hash)
    if fmt == HashFormat.DJANGO_PBKDF2: return _django_pbkdf2(password, original_hash)
    if fmt == HashFormat.ORACLE11G:     return _oracle11g(password, original_hash)
    if fmt in (HashFormat.MD5_SALT, HashFormat.SHA1_SALT, HashFormat.SHA256_SALT,
               HashFormat.HMAC_MD5, HashFormat.HMAC_SHA1, HashFormat.HMAC_SHA256):
        _, salt = _parse_salted(original_hash)
        salt_b  = salt.encode('utf-8', errors='replace')
        if fmt == HashFormat.MD5_SALT:    return hashlib.md5(salt_b + b).hexdigest() + ':' + salt
        if fmt == HashFormat.SHA1_SALT:   return hashlib.sha1(salt_b + b).hexdigest() + ':' + salt
        if fmt == HashFormat.SHA256_SALT: return hashlib.sha256(salt_b + b).hexdigest() + ':' + salt
        if fmt == HashFormat.HMAC_MD5:    return _hmac_mod.new(salt_b, b, hashlib.md5).hexdigest()    + ':' + salt
        if fmt == HashFormat.HMAC_SHA1:   return _hmac_mod.new(salt_b, b, hashlib.sha1).hexdigest()   + ':' + salt
        if fmt == HashFormat.HMAC_SHA256: return _hmac_mod.new(salt_b, b, hashlib.sha256).hexdigest() + ':' + salt
    return ""


def verify_hash(password: str, target_hash: str, fmt: HashFormat) -> bool:
    target = target_hash.strip()
    try:
        if fmt == HashFormat.BCRYPT:
            import bcrypt as _bcrypt
            return _bcrypt.checkpw(password.encode('utf-8'), target.encode('utf-8'))
        if fmt == HashFormat.WORDPRESS:
            return _wordpress_hash(password, target) == target
        if fmt == HashFormat.DJANGO_PBKDF2:
            return _django_pbkdf2(password, target) == target
        if fmt == HashFormat.ORACLE11G:
            return _oracle11g(password, target) == target
        if fmt in (HashFormat.MD5CRYPT, HashFormat.SHA512CRYPT, HashFormat.SHA256CRYPT):
            return compute_hash(password, fmt, original_hash=target) == target
        if fmt in (HashFormat.MD5_SALT, HashFormat.SHA1_SALT, HashFormat.SHA256_SALT,
                   HashFormat.HMAC_MD5, HashFormat.HMAC_SHA1, HashFormat.HMAC_SHA256):
            h, salt = _parse_salted(target)
            if not salt: return False
            computed = compute_hash(password, fmt, original_hash=target)
            c_hash, _ = _parse_salted(computed)
            return c_hash.lower() == h.lower()
        computed = compute_hash(password, fmt, original_hash=target)
        if not computed: return False
        return computed.lower() == target.lower()
    except Exception:
        return False


def _mp_check_batch(args_batch: list) -> list:
    matches = []
    for hash_str, password, fmt_value in args_batch:
        try:
            fmt = HashFormat(fmt_value)
            if verify_hash(password, hash_str, fmt):
                matches.append((hash_str, password))
        except Exception:
            pass
    return matches


# ---------------------------------------------------------------------------
# Rule Engine — JtR-compatible rule string parser (150+ built-in rules)
# ---------------------------------------------------------------------------

def _pos(ch: str) -> int:
    if ch.isdigit(): return int(ch)
    return ord(ch.upper()) - ord('A') + 10


def _char_class(ch: str) -> str:
    classes = {
        'v': 'aeiouAEIOU',
        'c': ''.join(c for c in string.ascii_letters if c.lower() not in 'aeiou'),
        'w': ' \t\r\n',
        'p': string.punctuation,
        's': string.punctuation + ' ',
        'l': string.ascii_lowercase,
        'u': string.ascii_uppercase,
        'd': string.digits,
        'a': string.ascii_letters,
        'x': ''.join(chr(i) for i in range(33, 127)),
        'z': string.printable,
    }
    return classes.get(ch, ch)


def apply_rule_string(password: str, rule: str) -> Optional[str]:
    """Apply a JtR-format rule string. Returns None if rule rejects password."""
    result = list(password)
    i = 0
    try:
        while i < len(rule):
            ch = rule[i]
            if   ch == ':': pass
            elif ch == 'l': result = [c.lower()     for c in result]
            elif ch == 'u': result = [c.upper()     for c in result]
            elif ch == 'c':
                if result:
                    result[0] = result[0].upper()
                    result[1:] = [c.lower() for c in result[1:]]
            elif ch == 'C':
                if result:
                    result[0] = result[0].lower()
                    result[1:] = [c.upper() for c in result[1:]]
            elif ch == 't': result = [c.swapcase()  for c in result]
            elif ch == 'T':
                i += 1
                if i < len(rule):
                    n = _pos(rule[i])
                    if n < len(result): result[n] = result[n].swapcase()
            elif ch == 'r': result = result[::-1]
            elif ch == 'd': result = result + result[:]
            elif ch == 'f': result = result + result[::-1]
            elif ch == '{': result = result[1:] + result[:1]
            elif ch == '}': result = result[-1:] + result[:-1]
            elif ch == '$':
                i += 1
                if i < len(rule): result.append(rule[i])
            elif ch == '^':
                i += 1
                if i < len(rule): result.insert(0, rule[i])
            elif ch == '[': result = result[1:]
            elif ch == ']': result = result[:-1]
            elif ch == 'D':
                i += 1
                if i < len(rule):
                    n = _pos(rule[i])
                    if n < len(result): del result[n]
            elif ch == 'x':
                i += 2
                if i < len(rule):
                    n = _pos(rule[i-1]); m = _pos(rule[i])
                    result = result[n:n+m]
            elif ch == 'O':
                i += 2
                if i < len(rule):
                    n = _pos(rule[i-1]); m = _pos(rule[i])
                    result = result[:n] + result[n+m:]
            elif ch == 'i':
                i += 2
                if i < len(rule):
                    n = _pos(rule[i-1]); x = rule[i]
                    result.insert(min(n, len(result)), x)
            elif ch == 'o':
                i += 2
                if i < len(rule):
                    n = _pos(rule[i-1]); x = rule[i]
                    if n < len(result): result[n] = x
            elif ch == 's':
                i += 2
                if i < len(rule):
                    x = rule[i-1]; y = rule[i]
                    result = [y if c == x else c for c in result]
            elif ch == '@':
                i += 1
                if i < len(rule):
                    x = rule[i]
                    result = [c for c in result if c != x]
            elif ch == 'z':
                i += 1
                if i < len(rule):
                    n = _pos(rule[i])
                    if result: result = [result[0]] * n + result
            elif ch == 'Z':
                i += 1
                if i < len(rule):
                    n = _pos(rule[i])
                    if result: result = result + [result[-1]] * n
            elif ch == 'q': result = [c for x in result for c in [x, x]]
            elif ch == 'k':
                if len(result) >= 2: result[0], result[1] = result[1], result[0]
            elif ch == 'K':
                if len(result) >= 2: result[-1], result[-2] = result[-2], result[-1]
            elif ch == 'E':
                new = []; prev = True
                for c in result:
                    if c == ' ': new.append(c); prev = True
                    elif prev:   new.append(c.upper()); prev = False
                    else:        new.append(c.lower())
                result = new
            elif ch == 'e':
                i += 1
                if i < len(rule):
                    x = rule[i]
                    new = []
                    for j, c in enumerate(result):
                        if j > 0: new.append(x)
                        new.append(c)
                    result = new
            elif ch == '>':
                i += 1
                if i < len(rule):
                    n = _pos(rule[i])
                    if len(result) <= n: return None
            elif ch == '<':
                i += 1
                if i < len(rule):
                    n = _pos(rule[i])
                    if len(result) >= n: return None
            elif ch == '_':
                i += 1
                if i < len(rule):
                    n = _pos(rule[i])
                    if len(result) != n: return None
            elif ch == '!':
                i += 1
                if i < len(rule):
                    if rule[i] == '?':
                        i += 1
                        if i < len(rule):
                            cls = _char_class(rule[i])
                            if any(c in cls for c in result): return None
                    else:
                        if rule[i] in result: return None
            elif ch == '/':
                i += 1
                if i < len(rule):
                    if rule[i] not in result: return None
            i += 1
    except Exception:
        pass
    return ''.join(result)


class RuleEngine:
    LEET: dict[str, str] = {'a':'@','e':'3','i':'1','o':'0','s':'$','t':'7','l':'1','b':'8','g':'9'}
    CURRENT_YEAR = time.localtime().tm_year

    JTR_RULES: list[str] = [
        # core transforms
        ':', 'l', 'u', 'c', 'C', 't', 'r', 'd', 'f', '{', '}', 'k', 'K', 'q', 'E',
        # append/prepend single digits
        '$0','$1','$2','$3','$4','$5','$6','$7','$8','$9',
        '^0','^1','^2','^3',
        # append/prepend symbols
        '$!','$@','$#','$.',
        # common suffixes
        '$1$2$3', '$1$2$3$4', '$0$0', '$9$9', '$0$1', '$6$9',
        # year appends (2020-2026)
        '$2$0$1$9','$2$0$2$0','$2$0$2$1','$2$0$2$2','$2$0$2$3','$2$0$2$4','$2$0$2$5',
        # capitalize + digit
        'c$1','c$2','c$3','c$4','c$5','c$!','c$@','c$1$2$3',
        # leet substitutions
        'sa@','se3','si1','so0','ss$','sl1','sb8','sg9',
        'sa@se3','sa@si1','se3si1','so0se3',
        'sa@se3si1','sa@se3so0','se3si1so0',
        'sa@se3si1so0',
        # leet + case
        'lsa@','lse3','lsi1','lso0',
        'csa@','cse3','cso0',
        'usa@','use3',
        # leet + append
        'sa@$1','se3$1','so0$1','si1$1',
        'sa@$!','se3$!',
        # reverse + append
        'r$1','r$2','r$!','rl$1',
        # double + modify
        'dl','du','dc','dt',
        # toggle + append
        't$1','t$!','t$0',
        # rotate
        '{$1','}{$1','}}$2',
        # duplicate first/last
        'z2','z3','Z2','Z3',
        # strip first/last
        '[','[l','[u','[c',
        ']',']l',']u',']c',
        ']$1',']$!',
        # insert
        'i0!','i0@','i01',
        # overwrite
        'o01','o02',
        # swap + case
        'kl','ku','Kl','Ku',
        # long-word guards + transform
        '>5c$!','>5c$1','>6c$1$2$3','>4l$1$2$3',
        '<8c$1','<9u$!',
        # double-reverse
        'fr','frl',
        # reflect + digit
        'f$1','f$!',
        # prepend + append year
        '^2$0$2$3','^2$0$2$4',
        # capitalize every word
        'E',
        # q (duplicate each char)
        'q',
        # extra combinations
        'c^1','c^2','c^!',
        'u^1','u^!',
        'r$1$2$3','r$2$0$2$3',
        'l$1$!','c$1$!','u$1$!',
        'l$!$1','c$!$1',
        '$1$!','$!$1','$1$@','$!$@$#',
        'd$!','d$1',
        # 2-digit suffixes
        '$0$1','$0$2','$0$3','$1$1','$2$2','$3$3',
        '$1$9$9$0','$1$9$9$5','$1$9$8$5','$1$9$9$9','$2$0$0$0',
    ]

    @classmethod
    def apply(cls, password: str) -> list[str]:
        variants: set[str] = set()
        for rule in cls.JTR_RULES:
            r = apply_rule_string(password, rule)
            if r is not None and r != password and len(r) <= 32:
                variants.add(r)
        # extra leet variants
        leet = ''.join(cls.LEET.get(c.lower(), c) for c in password)
        variants.update([leet, leet.upper(), leet.capitalize()])
        return list(variants)

    @classmethod
    def apply_single_rule(cls, password: str, rule: str) -> str:
        r = apply_rule_string(password, rule)
        return r if r is not None else password


# ---------------------------------------------------------------------------
# Keyboard Walk Engine
# ---------------------------------------------------------------------------

class KeyboardWalkEngine:
    QWERTY_H = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm']
    AZERTY_H = ['azertyuiop', 'qsdfghjklm', 'wxcvbn']
    DIGITS    = '1234567890'
    NUMPAD    = '789456123'
    DIAG_PAIRS = [
        'qwerty','qweasd','qazwsx','zxcvbn','asdfgh','sdfghj','xcvbnm',
        '1qaz2wsx','2wsx3edc','1qazxsw2','zaq1xsw2','plokijuh',
    ]

    @classmethod
    def generate(cls, min_len: int = 3, max_len: int = 10) -> Iterator[str]:
        seen: set[str] = set()
        def emit(s: str):
            if min_len <= len(s) <= max_len and s not in seen:
                seen.add(s); yield s
                if s.upper() != s:
                    u = s.upper()
                    if u not in seen: seen.add(u); yield u
                cap = s.capitalize()
                if cap not in seen: seen.add(cap); yield cap
                rev = s[::-1]
                if rev not in seen: seen.add(rev); yield rev

        for rows in [cls.QWERTY_H, cls.AZERTY_H]:
            for row in rows:
                for start in range(len(row)):
                    for length in range(min_len, min(max_len, len(row)-start) + 1):
                        yield from emit(row[start:start+length])

        for start in range(len(cls.DIGITS)):
            for length in range(min_len, min(max_len, len(cls.DIGITS)-start) + 1):
                s = cls.DIGITS[start:start+length]
                if s not in seen: seen.add(s); yield s
                yield cls.DIGITS[start:start+length][::-1]

        for start in range(len(cls.NUMPAD)):
            for length in range(min_len, min(max_len, len(cls.NUMPAD)-start) + 1):
                s = cls.NUMPAD[start:start+length]
                if s not in seen: seen.add(s); yield s

        for p in cls.DIAG_PAIRS:
            yield from emit(p)
            for suffix in ['1','123','!','@','1!']:
                yield from emit(p + suffix)
                yield from emit(p.capitalize() + suffix)


# ---------------------------------------------------------------------------
# Markov Chain Engine (trainable + built-in frequency tables)
# ---------------------------------------------------------------------------

BUILTIN_BIGRAMS: dict[str, str] = {
    'a':'sntrldicepmb', 'b':'earoluisy',  'c':'okaherlisum',
    'd':'eaoirsylum',   'e':'rsandtlico', 'f':'iorautle',
    'g':'aoeirhunlsm',  'h':'aeoirntsu',  'i':'nstercalov',
    'j':'oauei',        'k':'iesnaouyr',  'l':'eioalystu',
    'm':'aeoiuyns',     'n':'gseatdiou',  'o':'nrustoilmdb',
    'p':'areoislhut',   'q':'u',          'r':'eaisotnly',
    's':'aetiohsnuky',  't':'haeiorstnu', 'u':'snrtlicepb',
    'v':'eiao',         'w':'aieonh',     'x':'aepti',
    'y':'osneai',       'z':'aeoui',
    '0':'123456789',    '1':'234056789',  '2':'345016789',
    '3':'456012789',    '4':'567012389',  '5':'678012349',
    '6':'789012345',    '7':'890123456',  '8':'901234567',
    '9':'012345678',
}

COMMON_START = 'pasmjrdbtclhenfikwguo1234'


class MarkovEngine:
    def __init__(self, order: int = 2) -> None:
        self.order = order
        self.model: dict[str, list[tuple[str, float]]] = {}
        self._trained = False

    def train(self, words: Iterator[str]) -> None:
        counts: dict[str, Counter] = defaultdict(Counter)
        pad = '\x00' * self.order
        for word in words:
            padded = pad + word + '\x00'
            for i in range(len(word) + 1):
                ctx = padded[i:i + self.order]
                nxt = padded[i + self.order]
                counts[ctx][nxt] += 1
        self.model = {}
        for ctx, counter in counts.items():
            total = sum(counter.values())
            self.model[ctx] = sorted(
                [(ch, cnt / total) for ch, cnt in counter.items()],
                key=lambda x: -x[1]
            )
        self._trained = True

    def train_from_file(self, path: str) -> None:
        def _words():
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    w = line.strip()
                    if w: yield w
        self.train(_words())

    def _next_char(self, ctx: str) -> Optional[str]:
        if self._trained and ctx in self.model:
            chars, weights = zip(*self.model[ctx])
        else:
            last = ctx[-1] if ctx else ''
            chars_str = BUILTIN_BIGRAMS.get(last.lower(), string.ascii_lowercase)
            chars = list(chars_str)
            weights = [1.0 / len(chars)] * len(chars)
        chars_list = list(chars)
        total = sum(weights)
        r = random.random() * total
        acc = 0.0
        for c, w in zip(chars_list, weights):
            acc += w
            if r <= acc: return c
        return chars_list[-1] if chars_list else None

    def generate(
        self,
        min_len: int = 4,
        max_len: int = 8,
        max_candidates: int = 500_000,
    ) -> Iterator[str]:
        count = 0
        pad = '\x00' * self.order
        while count < max_candidates:
            word: list[str] = []
            ctx = pad
            start = random.choice(list(COMMON_START))
            word.append(start)
            ctx = (ctx + start)[-self.order:]
            for _ in range(max_len - 1):
                nxt = self._next_char(ctx)
                if not nxt or nxt == '\x00': break
                word.append(nxt)
                ctx = (ctx + nxt)[-self.order:]
            result = ''.join(word)
            if min_len <= len(result) <= max_len:
                yield result
                count += 1


# ---------------------------------------------------------------------------
# PRINCE Engine (element combination)
# ---------------------------------------------------------------------------

class PrinceEngine:
    @classmethod
    def generate(
        cls,
        elements: list[str],
        max_chains: int = 2,
        max_len: int = 16,
        rules: bool = False,
        max_candidates: int = 5_000_000,
    ) -> Iterator[str]:
        count = 0
        uniq = list(dict.fromkeys(e for e in elements if e))
        for e in uniq:
            if count >= max_candidates: return
            yield e; count += 1
            if rules:
                for v in RuleEngine.apply(e):
                    if count >= max_candidates: return
                    yield v; count += 1
        if max_chains >= 2:
            for e1, e2 in itertools.product(uniq, uniq):
                if count >= max_candidates: return
                combined = e1 + e2
                if len(combined) <= max_len:
                    yield combined; count += 1
                    if rules and count < max_candidates:
                        for v in RuleEngine.apply(combined):
                            if count >= max_candidates: return
                            yield v; count += 1
        if max_chains >= 3:
            for e1, e2, e3 in itertools.product(uniq[:500], uniq[:500], uniq[:500]):
                if count >= max_candidates: return
                combined = e1 + e2 + e3
                if len(combined) <= max_len:
                    yield combined; count += 1


# ---------------------------------------------------------------------------
# Pattern Engine — common password patterns
# ---------------------------------------------------------------------------

class PatternEngine:
    SEASONS   = ['spring', 'summer', 'autumn', 'winter', 'fall']
    MONTHS    = ['jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec',
                 'january','february','march','april','june','july','august',
                 'september','october','november','december']
    SUFFIXES  = ['123','1234','12345','!','!!','@','#','1!','1@','123!','2024','2023','01','99']
    PREFIXES  = ['123','!','@','the','my','mr','mrs','dr']
    SYMBOLS   = ['!','@','#','$','%','&','*']

    @classmethod
    def generate(cls, extra_words: Optional[list[str]] = None, max_candidates: int = 200_000) -> Iterator[str]:
        count = 0
        base_words = list(cls.SEASONS) + list(cls.MONTHS)
        if extra_words: base_words.extend(extra_words)
        yr = time.localtime().tm_year
        years = [str(y) for y in range(yr - 5, yr + 2)] + ['00','01','99','69','88']
        for w in base_words:
            for variant in [w, w.capitalize(), w.upper()]:
                for suf in cls.SUFFIXES:
                    if count >= max_candidates: return
                    yield variant + suf; count += 1
                for y in years:
                    if count >= max_candidates: return
                    yield variant + y; count += 1
                for pre in cls.PREFIXES:
                    if count >= max_candidates: return
                    yield pre + variant; count += 1
        for w1, w2 in itertools.product(base_words[:20], base_words[:20]):
            if count >= max_candidates: return
            combo = w1.capitalize() + w2.capitalize()
            yield combo; count += 1
            for suf in ['1','123','!']:
                if count >= max_candidates: return
                yield combo + suf; count += 1


# ---------------------------------------------------------------------------
# Association Engine — target/context-aware wordlist
# ---------------------------------------------------------------------------

class AssociationEngine:
    @classmethod
    def generate(cls, words: list[str], max_candidates: int = 100_000) -> Iterator[str]:
        count = 0
        yr = time.localtime().tm_year
        years = [str(y) for y in range(yr - 10, yr + 2)]
        special = ['!','@','#','$','1','12','123','1234','!@#','01','99']
        for w in words:
            for v in RuleEngine.apply(w):
                if count >= max_candidates: return
                yield v; count += 1
            for y in years:
                for suffix in ['', '!', '@', '#']:
                    if count >= max_candidates: return
                    yield w + y + suffix; count += 1
                    yield w.capitalize() + y + suffix; count += 1
            for s in special:
                if count >= max_candidates: return
                yield w + s; count += 1
                yield w.capitalize() + s; count += 1
            for w2 in words:
                if w != w2 and count < max_candidates:
                    yield w + w2; count += 1
                    yield w.capitalize() + w2.capitalize(); count += 1


# ---------------------------------------------------------------------------
# Mask Engine (Hashcat/JtR style)
# ---------------------------------------------------------------------------

class MaskEngine:
    CHARSETS: dict[str, str] = {
        '?l': string.ascii_lowercase,
        '?u': string.ascii_uppercase,
        '?d': string.digits,
        '?s': string.punctuation,
        '?a': string.printable.strip(),
        '?b': ''.join(chr(i) for i in range(256)),
        '?n': '\r\n',
        '?h': string.hexdigits[:16],
        '?H': string.hexdigits[:16].upper(),
    }

    @classmethod
    def parse(cls, mask: str, custom: Optional[dict[str, str]] = None) -> list[str]:
        all_cs = {**cls.CHARSETS, **(custom or {})}
        charsets: list[str] = []
        i = 0
        while i < len(mask):
            if mask[i] == '?' and i + 1 < len(mask):
                token = mask[i:i+2]
                charsets.append(all_cs.get(token, token[1]))
                i += 2
            else:
                charsets.append(mask[i])
                i += 1
        return charsets

    @classmethod
    def generate(cls, mask: str, max_candidates: int = 50_000_000,
                 custom: Optional[dict[str, str]] = None) -> Iterator[str]:
        charsets = cls.parse(mask, custom)
        count = 0
        for combo in itertools.product(*charsets):
            yield ''.join(combo)
            count += 1
            if count >= max_candidates: break

    @classmethod
    def estimate_size(cls, mask: str) -> int:
        charsets = cls.parse(mask)
        if not charsets: return 0
        total = 1
        for cs in charsets:
            total *= len(cs)
            if total > 10**15: return 10**15
        return total


# ---------------------------------------------------------------------------
# Incremental Engine (brute force with frequency-ordered charsets)
# ---------------------------------------------------------------------------

CHARSET_NAMES: dict[str, str] = {
    'alpha':   string.ascii_lowercase,
    'lower':   string.ascii_lowercase,
    'upper':   string.ascii_uppercase,
    'alnum':   string.ascii_letters + string.digits,
    'digits':  string.digits,
    'hex':     '0123456789abcdef',
    'all':     string.ascii_letters + string.digits + string.punctuation,
    'ascii':   ''.join(chr(i) for i in range(32, 127)),
    'lm':      string.ascii_uppercase + string.digits + string.punctuation,
    'freq':    'etaoinshrdlcumwfgypbvkjxqz0123456789!@#$',
}


class IncrementalEngine:
    @classmethod
    def generate(
        cls,
        charset: str = 'all',
        min_len: int = 1,
        max_len: int = 6,
        max_candidates: int = 50_000_000,
    ) -> Iterator[str]:
        chars = CHARSET_NAMES.get(charset.lower(), charset)
        count = 0
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(chars, repeat=length):
                yield ''.join(combo)
                count += 1
                if count >= max_candidates: return


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------

class SessionManager:
    BASE = Path.home() / '.phantomrecon' / 'sessions'

    def __init__(self, name: str = 'default') -> None:
        self.name = name
        self.path = self.BASE / f'{name}.session'
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, state: dict) -> None:
        with open(self.path, 'wb') as f:
            pickle.dump(state, f)

    def load(self) -> Optional[dict]:
        if self.path.exists():
            try:
                with open(self.path, 'rb') as f:
                    return pickle.load(f)
            except Exception:
                return None
        return None

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()

    @classmethod
    def list_sessions(cls) -> list[str]:
        cls.BASE.mkdir(parents=True, exist_ok=True)
        return [p.stem for p in cls.BASE.glob('*.session')]


# ---------------------------------------------------------------------------
# Crack Statistics (real-time H/s + ETA)
# ---------------------------------------------------------------------------

class CrackStats:
    def __init__(self) -> None:
        self.start_time   = time.time()
        self.attempts     = 0
        self.cracked      = 0
        self._last_time   = time.time()
        self._last_att    = 0
        self._hps: float  = 0.0
        self._lock        = threading.Lock()

    def update(self, attempts: int, cracked: int) -> None:
        with self._lock:
            now = time.time()
            dt  = now - self._last_time
            if dt >= 0.5:
                da = attempts - self._last_att
                self._hps      = da / dt
                self._last_time = now
                self._last_att  = attempts
            self.attempts = attempts
            self.cracked  = cracked

    @property
    def hps(self) -> float:
        return self._hps

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    def eta(self, total_hint: int) -> str:
        if total_hint <= 0 or self._hps <= 0:
            return '?'
        remaining = max(0, total_hint - self.attempts)
        secs = remaining / self._hps
        if secs > 86400: return f"{secs/86400:.1f}d"
        if secs > 3600:  return f"{secs/3600:.1f}h"
        if secs > 60:    return f"{secs/60:.1f}m"
        return f"{secs:.0f}s"

    def format_hps(self) -> str:
        h = self._hps
        if h >= 1_000_000: return f"{h/1_000_000:.1f}MH/s"
        if h >= 1_000:     return f"{h/1_000:.1f}kH/s"
        return f"{h:.0f}H/s"

    def summary_line(self, attack: str, total_hint: int = 0) -> str:
        eta = self.eta(total_hint)
        return (f"  [{attack}] {self.attempts:>10,} tried | "
                f"{self.format_hps():>10} | "
                f"{self.cracked} cracked | "
                f"elapsed {self.elapsed:.1f}s | ETA {eta}")


# ---------------------------------------------------------------------------
# Pot File
# ---------------------------------------------------------------------------

class PotFile:
    DEFAULT_PATH = Path.home() / '.phantomrecon' / 'john.pot'

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else self.DEFAULT_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            for line in self.path.read_text(errors='replace').splitlines():
                if ':' in line:
                    h, _, p = line.partition(':')
                    self._cache[h.strip().lower()] = p.strip()

    def get(self, hash_str: str) -> Optional[str]:
        return self._cache.get(hash_str.strip().lower())

    def save(self, hash_str: str, password: str) -> None:
        key = hash_str.strip().lower()
        if key not in self._cache:
            self._cache[key] = password
            with open(self.path, 'a', encoding='utf-8') as f:
                f.write(f"{hash_str}:{password}\n")

    def list_all(self) -> list[tuple[str, str]]:
        return list(self._cache.items())

    def stats(self) -> dict[str, int]:
        return {'cracked': len(self._cache)}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class CrackResult:
    hash_str:  str
    password:  Optional[str]
    fmt:       HashFormat
    cracked:   bool
    attack:    str
    attempts:  int
    elapsed:   float
    source:    str = ""


ProgressCallback = Callable[[int, int, str, str], None]


# ---------------------------------------------------------------------------
# Main Cracker — JohnCracker
# ---------------------------------------------------------------------------

class JohnCracker:
    def __init__(
        self,
        hashes:      list[str],
        fmt:         Optional[HashFormat] = None,
        pot_file:    Optional[str]        = None,
        threads:     int                  = 4,
        progress_cb: Optional[ProgressCallback] = None,
        verbose:     bool                 = False,
        session:     Optional[str]        = None,
        use_mp:      bool                 = True,
    ) -> None:
        self.hashes      = [h.strip() for h in hashes if h.strip()]
        self.fmt         = fmt
        self.pot         = PotFile(pot_file)
        self.threads     = max(1, threads)
        self.progress_cb = progress_cb
        self.verbose     = verbose
        self.use_mp      = use_mp and multiprocessing.cpu_count() > 1
        self._stopped    = False
        self.results:    dict[str, CrackResult] = {}
        self.stats       = CrackStats()
        self._session    = SessionManager(session) if session else None
        self._markov     = MarkovEngine()
        self._markov_trained = False

    # -- helpers -------------------------------------------------------------

    def stop(self) -> None:
        self._stopped = True

    def _resolve_format(self, hash_str: str) -> HashFormat:
        if self.fmt: return self.fmt
        return HashIdentifier.identify_best(hash_str)

    def _remaining(self) -> list[str]:
        return [h for h in self.hashes if h not in self.results]

    def _check_pot(self) -> None:
        for h in list(self.hashes):
            cached = self.pot.get(h)
            if cached is not None:
                self.results[h] = CrackResult(
                    hash_str=h, password=cached,
                    fmt=self._resolve_format(h),
                    cracked=True, attack="pot",
                    attempts=0, elapsed=0.0, source="pot_file",
                )

    def _crack_one(self, hash_str: str, password: str, fmt: HashFormat) -> bool:
        try:
            return verify_hash(password, hash_str, fmt)
        except Exception:
            return False

    # -- core candidate runner (multiprocessing aware) -----------------------

    def _run_candidates(
        self,
        candidates:  Iterator[str],
        attack_name: str,
        total_hint:  int = 0,
    ) -> None:
        remaining = self._remaining()
        if not remaining or self._stopped: return

        fmt_map   = {h: self._resolve_format(h) for h in remaining}
        start     = time.time()
        attempts  = 0
        BATCH     = 1000

        def _process_batch(batch: list[str]) -> None:
            nonlocal attempts
            still = self._remaining()
            if not still: return

            if self.use_mp and len(batch) * len(still) > 500:
                args = [(h, pwd, fmt_map[h].value)
                        for pwd in batch for h in still if h not in self.results]
                chunk_size = max(50, len(args) // (self.threads * 2))
                chunks = [args[i:i+chunk_size] for i in range(0, len(args), chunk_size)]
                with ProcessPoolExecutor(max_workers=self.threads) as ex:
                    fts = {ex.submit(_mp_check_batch, chunk): chunk for chunk in chunks}
                    for ft in as_completed(fts):
                        try:
                            for h, pwd in ft.result():
                                if h not in self.results:
                                    self.results[h] = CrackResult(
                                        hash_str=h, password=pwd,
                                        fmt=fmt_map[h], cracked=True,
                                        attack=attack_name,
                                        attempts=attempts,
                                        elapsed=time.time()-start,
                                    )
                                    self.pot.save(h, pwd)
                                    if self.verbose:
                                        print(f"\r  [+] CRACKED  {h[:40]}  →  {pwd}", flush=True)
                        except Exception:
                            pass
            else:
                with ThreadPoolExecutor(max_workers=self.threads) as ex:
                    fts = {}
                    for pwd in batch:
                        for h in still:
                            if h not in self.results:
                                ft = ex.submit(self._crack_one, h, pwd, fmt_map[h])
                                fts[ft] = (h, pwd)
                    for ft in as_completed(fts):
                        h, pwd = fts[ft]
                        try:
                            if ft.result() and h not in self.results:
                                self.results[h] = CrackResult(
                                    hash_str=h, password=pwd,
                                    fmt=fmt_map[h], cracked=True,
                                    attack=attack_name,
                                    attempts=attempts,
                                    elapsed=time.time()-start,
                                )
                                self.pot.save(h, pwd)
                                if self.verbose:
                                    print(f"\r  [+] CRACKED  {h[:40]}  →  {pwd}", flush=True)
                        except Exception:
                            pass

        batch: list[str] = []
        for pwd in candidates:
            if self._stopped or not self._remaining(): break
            batch.append(pwd)
            attempts += 1
            self.stats.update(attempts, len(self.results))
            if self.progress_cb and attempts % 500 == 0:
                self.progress_cb(attempts, total_hint, attack_name, pwd)
            if len(batch) >= BATCH:
                _process_batch(batch)
                batch.clear()

        if batch and self._remaining():
            _process_batch(batch)

        elapsed = time.time() - start
        for h in self._remaining():
            if h not in self.results:
                self.results.setdefault(h, CrackResult(
                    hash_str=h, password=None, fmt=fmt_map.get(h, HashFormat.UNKNOWN),
                    cracked=False, attack=attack_name, attempts=attempts, elapsed=elapsed,
                ))

    # -- attack methods ------------------------------------------------------

    def single_attack(self) -> None:
        COMMON = [
            "password","123456","12345678","qwerty","abc123","monkey","letmein",
            "trustno1","dragon","master","sunshine","ashley","passw0rd","shadow",
            "123123","superman","michael","football","baseball","welcome","login",
            "admin","root","pass","test","guest","user","default","changeme",
            "secret","password1","password123","iloveyou","princess","rockyou",
            "mustang","access","hello","hunter","ranger","soccer","starwars",
            "batman","zaq1zaq1","q1w2e3r4","1q2w3e4r","letmein1","P@ssw0rd",
            "Summer2023","Winter2023","Spring2024","Autumn2023",
            "January1","February1","Admin123","Admin@123",
        ]
        variants: set[str] = set()
        for w in COMMON:
            variants.add(w)
            variants.update(RuleEngine.apply(w))
        self._run_candidates(iter(variants), "single")

    def dictionary_attack(self, wordlist_path: str, rules: bool = False) -> None:
        def _gen():
            path = Path(wordlist_path)
            if not path.exists():
                raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
            seen: set[str] = set()
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    word = line.rstrip('\n\r')
                    if not word or word in seen: continue
                    seen.add(word)
                    yield word
                    if rules:
                        for v in RuleEngine.apply(word):
                            if v not in seen:
                                seen.add(v); yield v
        self._run_candidates(_gen(), "dictionary" + ("+rules" if rules else ""))

    def incremental_attack(
        self,
        charset: str = 'all',
        min_len: int = 1,
        max_len: int = 6,
        max_candidates: int = 50_000_000,
    ) -> None:
        gen = IncrementalEngine.generate(charset, min_len, max_len, max_candidates)
        self._run_candidates(gen, f"incremental[{charset}:{min_len}-{max_len}]", max_candidates)

    def mask_attack(self, mask: str, max_candidates: int = 50_000_000) -> None:
        size = MaskEngine.estimate_size(mask)
        gen  = MaskEngine.generate(mask, max_candidates)
        self._run_candidates(gen, f"mask[{mask}]", min(size, max_candidates))

    def hybrid_wordlist_mask(self, wordlist_path: str, mask: str,
                             max_candidates: int = 10_000_000) -> None:
        mask_chars = MaskEngine.parse(mask)
        def _gen():
            with open(wordlist_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    word = line.rstrip('\n\r')
                    if not word: continue
                    for suffix in itertools.islice(
                            (''.join(c) for c in itertools.product(*mask_chars)),
                            10_000):
                        yield word + suffix
        self._run_candidates(_gen(), f"hybrid-wm[{mask}]", max_candidates)

    def hybrid_mask_wordlist(self, mask: str, wordlist_path: str,
                             max_candidates: int = 10_000_000) -> None:
        mask_chars = MaskEngine.parse(mask)
        def _gen():
            with open(wordlist_path, 'r', encoding='utf-8', errors='replace') as f:
                words = [l.rstrip('\n\r') for l in f if l.strip()]
            for prefix in itertools.islice(
                    (''.join(c) for c in itertools.product(*mask_chars)), 10_000):
                for word in words:
                    yield prefix + word
        self._run_candidates(_gen(), f"hybrid-mw[{mask}]", max_candidates)

    def combinator_attack(self, wordlist1: str, wordlist2: str,
                          rules: bool = False,
                          max_candidates: int = 10_000_000) -> None:
        def _load(p): return [l.rstrip('\n\r') for l in open(p,'r',encoding='utf-8',errors='replace') if l.strip()]
        w1 = _load(wordlist1); w2 = _load(wordlist2)
        def _gen():
            count = 0
            for a, b in itertools.product(w1, w2):
                combined = a + b
                yield combined; count += 1
                if rules:
                    for v in RuleEngine.apply(combined):
                        yield v; count += 1
                if count >= max_candidates: return
        self._run_candidates(_gen(), "combinator", max_candidates)

    def prince_attack(self, wordlist_path: str, max_chains: int = 2,
                      rules: bool = False, max_candidates: int = 5_000_000) -> None:
        elements = []
        with open(wordlist_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                w = line.strip()
                if w: elements.append(w)
                if len(elements) >= 100_000: break
        gen = PrinceEngine.generate(elements, max_chains=max_chains,
                                    rules=rules, max_candidates=max_candidates)
        self._run_candidates(gen, f"prince[chains={max_chains}]", max_candidates)

    def markov_attack(
        self,
        min_len: int = 4,
        max_len: int = 8,
        train_file: Optional[str] = None,
        max_candidates: int = 500_000,
    ) -> None:
        if train_file and not self._markov_trained:
            self._markov.train_from_file(train_file)
            self._markov_trained = True
        gen = self._markov.generate(min_len, max_len, max_candidates)
        self._run_candidates(gen, f"markov[{min_len}-{max_len}]", max_candidates)

    def keyboard_attack(self, min_len: int = 3, max_len: int = 10) -> None:
        gen = KeyboardWalkEngine.generate(min_len, max_len)
        self._run_candidates(gen, "keyboard")

    def pattern_attack(self, extra_words: Optional[list[str]] = None,
                       max_candidates: int = 200_000) -> None:
        gen = PatternEngine.generate(extra_words, max_candidates)
        self._run_candidates(gen, "pattern", max_candidates)

    def association_attack(self, words: list[str],
                           max_candidates: int = 100_000) -> None:
        gen = AssociationEngine.generate(words, max_candidates)
        self._run_candidates(gen, "association", max_candidates)

    def wordlist_from_target(self, words: list[str]) -> None:
        self.association_attack(words)

    # -- run all -------------------------------------------------------------

    def run_all(
        self,
        wordlist:        Optional[str]        = None,
        wordlist2:       Optional[str]        = None,
        rules:           bool                 = False,
        incremental:     bool                 = False,
        charset:         str                  = 'all',
        min_len:         int                  = 1,
        max_len:         int                  = 6,
        mask:            Optional[str]        = None,
        single:          bool                 = True,
        markov:          bool                 = False,
        markov_train:    Optional[str]        = None,
        markov_min:      int                  = 4,
        markov_max:      int                  = 8,
        keyboard:        bool                 = False,
        prince:          bool                 = False,
        prince_chains:   int                  = 2,
        combinator:      bool                 = False,
        hybrid_wm:       bool                 = False,
        hybrid_mw:       bool                 = False,
        pattern:         bool                 = False,
        association:     bool                 = False,
        association_words: Optional[list[str]] = None,
        max_candidates:  int                  = 50_000_000,
        restore:         bool                 = False,
    ) -> dict[str, CrackResult]:

        if restore and self._session:
            state = self._session.load()
            if state:
                self.results = state.get('results', {})

        self._check_pot()
        if not self._remaining(): return self.results

        if single:
            self.single_attack()
        if keyboard and self._remaining():
            self.keyboard_attack(min_len, min(max_len, 10))
        if pattern and self._remaining():
            self.pattern_attack(max_candidates=min(200_000, max_candidates))
        if wordlist and self._remaining():
            self.dictionary_attack(wordlist, rules=rules)
        if combinator and wordlist and wordlist2 and self._remaining():
            self.combinator_attack(wordlist, wordlist2, rules=rules)
        if prince and wordlist and self._remaining():
            self.prince_attack(wordlist, max_chains=prince_chains, rules=rules)
        if hybrid_wm and wordlist and mask and self._remaining():
            self.hybrid_wordlist_mask(wordlist, mask)
        if hybrid_mw and wordlist and mask and self._remaining():
            self.hybrid_mask_wordlist(mask, wordlist)
        if mask and not hybrid_wm and not hybrid_mw and self._remaining():
            self.mask_attack(mask, max_candidates)
        if markov and self._remaining():
            self.markov_attack(markov_min, markov_max, markov_train, max_candidates)
        if association and association_words and self._remaining():
            self.association_attack(association_words)
        if incremental and self._remaining():
            self.incremental_attack(charset, min_len, max_len, max_candidates)

        for h in self.hashes:
            if h not in self.results:
                self.results[h] = CrackResult(
                    hash_str=h, password=None, fmt=self._resolve_format(h),
                    cracked=False, attack="none", attempts=0, elapsed=0.0,
                )

        if self._session:
            self._session.save({'results': self.results})

        return self.results


# ---------------------------------------------------------------------------
# File loaders
# ---------------------------------------------------------------------------

def load_hashes_from_file(path: str) -> list[str]:
    hashes = []
    seen: set[str] = set()
    for line in Path(path).read_text(errors='replace').splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        if ':' in line:
            parts = line.split(':')
            h = parts[1].strip() if len(parts) > 1 and len(parts[0]) < 32 else parts[0].strip()
        else:
            h = line
        if h and h not in seen:
            seen.add(h); hashes.append(h)
    return hashes


def load_shadow_file(path: str) -> list[tuple[str, str]]:
    entries = []
    for line in Path(path).read_text(errors='replace').splitlines():
        if ':' not in line: continue
        parts = line.split(':')
        if len(parts) < 2: continue
        user, pw = parts[0], parts[1]
        if pw and pw not in ('x', '*', '!', '', '!!', '*!!'):
            entries.append((user, pw))
    return entries


def load_passwd_shadow(passwd_path: str, shadow_path: str) -> list[tuple[str, str]]:
    entries = []
    for line in Path(shadow_path).read_text(errors='replace').splitlines():
        parts = line.split(':')
        if len(parts) >= 2 and parts[1] not in ('x', '*', '!', '', '!!'):
            entries.append((parts[0], parts[1]))
    return entries


# ---------------------------------------------------------------------------
# Enhanced results formatter
# ---------------------------------------------------------------------------

def format_results_table(
    results: dict[str, CrackResult],
    show_failed: bool = False,
    usernames: Optional[dict[str, str]] = None,
) -> str:
    usernames = usernames or {}
    lines = []
    cracked = [r for r in results.values() if r.cracked]
    failed  = [r for r in results.values() if not r.cracked]
    total_attempts = sum(r.attempts for r in results.values())

    lines.append(f"\n{'═'*82}")
    lines.append(f"  JOHN THE RIPPER — SESSION RESULTS")
    lines.append(f"{'═'*82}")
    lines.append(f"  Total hashes : {len(results)}")
    lines.append(f"  Cracked      : {len(cracked)}  ({len(cracked)/max(1,len(results))*100:.1f}%)")
    lines.append(f"  Uncracked    : {len(failed)}")
    lines.append(f"  Candidates   : {total_attempts:,}")

    if cracked:
        attack_groups: dict[str, list[CrackResult]] = defaultdict(list)
        for r in cracked:
            attack_groups[r.attack].append(r)
        lines.append(f"\n  Attack breakdown:")
        for atk, rs in sorted(attack_groups.items(), key=lambda x: -len(x[1])):
            lines.append(f"    {atk:<30} {len(rs)} cracked")

    lines.append(f"{'─'*82}")

    if cracked:
        lines.append(f"\n  {'USER':<16} {'HASH':<44} {'FORMAT':<14} {'PASSWORD':<20} {'ATTACK'}")
        lines.append(f"  {'─'*16} {'─'*44} {'─'*14} {'─'*20} {'─'*14}")
        for r in sorted(cracked, key=lambda x: x.attack):
            h     = r.hash_str[:42] + '..' if len(r.hash_str) > 44 else r.hash_str
            user  = usernames.get(r.hash_str, '')[:14]
            lines.append(
                f"  {user:<16} {h:<44} {r.fmt.value:<14} {r.password or '':<20} {r.attack}"
            )

    if show_failed and failed:
        lines.append(f"\n  {'HASH':<50} {'FORMAT':<14} STATUS")
        lines.append(f"  {'─'*50} {'─'*14} ──────")
        for r in failed:
            h = r.hash_str[:48] + '..' if len(r.hash_str) > 50 else r.hash_str
            lines.append(f"  {h:<50} {r.fmt.value:<14} NOT CRACKED")

    lines.append(f"{'═'*82}\n")
    return '\n'.join(lines)

