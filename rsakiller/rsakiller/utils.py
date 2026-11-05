"""整数、编码、多项式基础工具。

全部基于 Python int + gmpy2，不依赖 Sage。
"""
from __future__ import annotations

import math
import re
import struct
from typing import Iterable, List, Optional, Sequence, Tuple

import gmpy2


# --------------------------------------------------------------------------
# 基本整数运算
# --------------------------------------------------------------------------
def iroot(n: int, k: int) -> Tuple[int, bool]:
    """整数 k 次根，返回 (根, 是否精确)。"""
    if n < 0:
        raise ValueError("iroot 需要非负整数")
    if n == 0:
        return 0, True
    r, exact = gmpy2.iroot(gmpy2.mpz(n), k)
    return int(r), bool(exact)


def isqrt(n: int) -> int:
    return int(gmpy2.isqrt(gmpy2.mpz(n)))


def is_square(n: int) -> bool:
    if n < 0:
        return False
    return bool(gmpy2.is_square(gmpy2.mpz(n)))


def gcd(a: int, b: int) -> int:
    return int(gmpy2.gcd(gmpy2.mpz(a), gmpy2.mpz(b)))


def nbit(n: int) -> int:
    return int(n).bit_length()


def inv(a: int, m: int) -> Optional[int]:
    """模逆，不存在返回 None。"""
    a %= m
    g = gcd(a, m)
    if g != 1:
        return None
    return int(gmpy2.invert(gmpy2.mpz(a), gmpy2.mpz(m)))


def powmod(b: int, e: int, m: int) -> int:
    return int(gmpy2.powmod(gmpy2.mpz(b), gmpy2.mpz(e), gmpy2.mpz(m)))


def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    return bool(gmpy2.is_prime(gmpy2.mpz(n), 25))


# --------------------------------------------------------------------------
# 编码转换
# --------------------------------------------------------------------------
def long_to_bytes(n: int, block_size: int = 0) -> bytes:
    if n == 0:
        b = b"\x00"
    else:
        length = (n.bit_length() + 7) // 8
        b = n.to_bytes(length, "big")
    if block_size:
        if len(b) > block_size:
            return b
        b = b"\x00" * (block_size - len(b)) + b
    return b


def bytes_to_long(b: bytes) -> int:
    return int.from_bytes(b, "big")


def int_to_hex(n: int) -> str:
    if n is None:
        return "None"
    h = format(n, "x")
    return "0x" + h


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return ok / len(b)


def guess_text(n: int) -> Optional[bytes]:
    """把整数尽量还原成可读串；不像文本就返回 None。

    同时尝试大端/小端，避免因题目的字节序把结果判掉。
    """
    res: List[bytes] = []
    for bs in (long_to_bytes(n),):
        res.append(bs)
        res.append(bs[::-1])
        # 去掉可能的 0x00 前缀
        if bs.startswith(b"\x00"):
            res.append(bs.lstrip(b"\x00"))
    best = None
    best_score = 0.0
    for cand in res:
        if len(cand) < 3:
            continue
        score = printable_ratio(cand)
        # 有花括号包裹的强烈认为是 flag
        if b"{" in cand and b"}" in cand:
            score += 1.0
        if score > best_score:
            best_score, best = score, cand
    if best is not None and best_score >= 0.85:
        return best
    return None


# --------------------------------------------------------------------------
# 中国剩余定理
# --------------------------------------------------------------------------
def crt(pairs: Sequence[Tuple[int, int]]) -> Tuple[Optional[int], int]:
    """广义 CRT。返回 (解, 模数)；无解时解为 None。"""
    x, M = 0, 1
    for a, m in pairs:
        if m <= 0:
            raise ValueError("模数必须为正")
        a %= m
        g = gcd(M, m)
        if (a - x) % g != 0:
            return None, M * m // g if g else M
        # 合并
        m1, m2 = M // g, m // g
        t = ((a - x) // g * inv(m1, m2)) % m2 if m2 > 1 else 0
        x = x + M * t
        M = M * m2
        x %= M
    return x % M if M else None, M


# --------------------------------------------------------------------------
# 连分数（Wiener 攻击用）
# --------------------------------------------------------------------------
def continued_fraction(num: int, den: int) -> List[int]:
    cf: List[int] = []
    while den:
        q, r = divmod(num, den)
        cf.append(q)
        num, den = den, r
    return cf


def convergents(cf: Sequence[int]) -> Iterable[Tuple[int, int]]:
    """生成 (分子, 分母) 收敛子。"""
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for a in cf:
        n0, n1 = n1, a * n1 + n0
        d0, d1 = d1, a * d1 + d0
        yield n1, d1


# --------------------------------------------------------------------------
# 多项式（系数用从低到高的 int 列表表示，模 N 运算）
# --------------------------------------------------------------------------
Poly = List[int]


def poly_trim(p: Poly) -> Poly:
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def poly_mul(a: Poly, b: Poly) -> Poly:
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    out[i + j] += ai * bj
    return poly_trim(out)


def poly_mulmod(a: Poly, b: Poly, n: int) -> Poly:
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    out[i + j] = (out[i + j] + ai * bj) % n
    return poly_trim(out)


def poly_addmod(a: Poly, b: Poly, n: int) -> Poly:
    L = max(len(a), len(b))
    out = [0] * L
    for i in range(L):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % n
    return poly_trim(out)


def poly_submod(a: Poly, b: Poly, n: int) -> Poly:
    L = max(len(a), len(b))
    out = [0] * L
    for i in range(L):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % n
    return poly_trim(out)


def poly_divmod(a: Poly, b: Poly, n: int):
    """Z_n[x] 上的带余除法。若首项不可逆，返回 (None, 因子)。"""
    a = poly_trim([x % n for x in a])
    b = poly_trim([x % n for x in b])
    if len(b) == 1 and b[0] == 0:
        return None, None
    inv_lc = inv(b[-1], n)
    if inv_lc is None:
        f = gcd(b[-1], n)
        if 1 < f < n:
            return None, f
        return None, None
    q = [0] * max(1, len(a) - len(b) + 1)
    r = a[:]
    while len(r) >= len(b) and not (len(r) == 1 and r[0] == 0):
        deg = len(r) - len(b)
        coef = r[-1] * inv_lc % n
        q[deg] = coef
        for i, bi in enumerate(b):
            r[deg + i] = (r[deg + i] - coef * bi) % n
        r = poly_trim(r)
        if len(r) == 1 and r[0] == 0:
            break
    return poly_trim(q), poly_trim(r)


def poly_gcd_mod(a: Poly, b: Poly, n: int):
    """Z_n[x] 上求 gcd 并首一化。

    返回 (gcd, 意外因子)。欧几里得过程中若遇到不可逆首项，
    说明顺手分解了 n —— 这在 CTF 里反而是意外之喜。
    """
    a = poly_trim([x % n for x in a])
    b = poly_trim([x % n for x in b])
    while not (len(b) == 1 and b[0] == 0):
        _, r = poly_divmod(a, b, n)
        if r is None:
            # 除不动：拿到了 n 的因子
            f = gcd(poly_trim(b)[-1], n)
            return None, (f if 1 < f < n else None)
        a, b = b, r
    lc = a[-1] % n
    iv = inv(lc, n)
    if iv is None:
        return None, gcd(lc, n)
    return [(c * iv) % n for c in a], None


def poly_eval_mod(p: Poly, x: int, n: int) -> int:
    r = 0
    for c in reversed(p):
        r = (r * x + c) % n
    return r


def poly_from_int_roots(roots: Sequence[int]) -> Poly:
    p: Poly = [1]
    for r in roots:
        p = poly_mul(p, [-r, 1])
    return p
