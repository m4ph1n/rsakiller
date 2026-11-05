"""纯 Python 格基约减（LLL）与 Coppersmith 小根求解。

不依赖 fpylll / Sage：Gram-Schmidt 用 gmpy2.mpfr 做高精度浮点，
向量运算仍用精确整数，精度按输入位宽自动放大。

适用规模：维度 <= 40。Coppersmith 单变量场景（e=3, 已知明文/因子高位）
一般在 4~15 维，纯 Python 完全够用。
"""
from __future__ import annotations

import itertools
import math
from typing import List, Optional, Sequence

import gmpy2
from gmpy2 import mpfr, mpz

from . import utils as U

Matrix = List[List[int]]


# --------------------------------------------------------------------------
# LLL
# --------------------------------------------------------------------------
def _max_bits(B: Matrix) -> int:
    return max((abs(int(x)).bit_length() for row in B for x in row), default=1)


def lll_reduce(B: Matrix, delta: float = 0.75, precision: Optional[int] = None) -> Matrix:
    """对行向量构成的整数矩阵做 LLL 约减，返回新矩阵（不修改入参）。"""
    n = len(B)
    if n <= 1:
        return [list(map(int, row)) for row in B]
    m = len(B[0])
    maxb = _max_bits(B)
    prec = precision if precision else max(256, 2 * maxb + 128)

    ctx = gmpy2.context(precision=prec)
    with ctx:
        A = [[mpz(int(x)) for x in row] for row in B]
        mu = [[mpfr(0)] * n for _ in range(n)]
        Bs = [mpfr(0)] * n
        Bstar: List[List[mpfr]] = [[mpfr(0)] * m for _ in range(n)]

        def gs_row(k: int) -> None:
            v = [mpfr(A[k][i]) for i in range(m)]
            for j in range(k):
                if Bs[j] == 0:
                    mu[k][j] = mpfr(0)
                    continue
                dot = mpfr(0)
                bs = Bstar[j]
                for i in range(m):
                    dot += v[i] * bs[i]
                c = dot / Bs[j]
                mu[k][j] = c
                if c != 0:
                    for i in range(m):
                        v[i] -= c * bs[i]
            Bstar[k] = v
            s = mpfr(0)
            for i in range(m):
                s += v[i] * v[i]
            Bs[k] = s

        gs_row(0)
        k = 1
        guard = 0
        max_guard = 400 * n * n + 8000
        while k < n:
            guard += 1
            if guard > max_guard:
                break
            # 尺寸约减
            for j in range(k - 1, -1, -1):
                if Bs[j] == 0:
                    continue
                q = int(gmpy2.rint(mu[k][j])) if mu[k][j] != 0 else 0
                if q:
                    for i in range(m):
                        A[k][i] -= q * A[j][i]
                    gs_row(k)
            # Lovász 条件
            if Bs[k] >= (mpfr(delta) - mu[k][k - 1] * mu[k][k - 1]) * Bs[k - 1]:
                k += 1
            else:
                A[k], A[k - 1] = A[k - 1], A[k]
                # 交换后 k-1 及其之后所有行的 GS 都失效，整体重算
                for kk in range(k - 1, n):
                    gs_row(kk)
                k = max(k - 1, 1)
        return [[int(x) for x in row] for row in A]


# --------------------------------------------------------------------------
# 整数多项式求根
# --------------------------------------------------------------------------
def int_roots(coeffs: Sequence[int]) -> List[int]:
    """求整系数多项式的所有整数根。"""
    coeffs = list(coeffs)
    while len(coeffs) > 1 and coeffs[-1] == 0:
        coeffs.pop()
    if len(coeffs) <= 1:
        return []
    try:
        from sympy import Poly, Symbol

        x = Symbol("x")
        expr = sum(int(c) * x ** i for i, c in enumerate(coeffs))
        p = Poly(expr, x)
        rr = p.ground_roots()
        out = []
        for r, mult in rr.items():
            if r.is_Integer:
                out.append(int(r))
        return out
    except Exception:
        return []


# --------------------------------------------------------------------------
# Coppersmith（单变量，Howgrave-Graham 构造）
# --------------------------------------------------------------------------
def _poly_from_coeffs(coeffs: Sequence[int]) -> List[int]:
    c = [int(x) for x in coeffs]
    while len(c) > 1 and c[-1] == 0:
        c.pop()
    return c


def _poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[i + j] += ai * bj
    return out


def _poly_shift(p, k):
    return [0] * k + list(p)


def coppersmith_univariate(
    f_coeffs: Sequence[int],
    N: int,
    beta: float = 1.0,
    X: Optional[int] = None,
    m: Optional[int] = None,
    t: Optional[int] = None,
    epsilon: Optional[float] = None,
    verbose: bool = False,
) -> List[int]:
    """求 f(x) ≡ 0 (mod b) 的小根，其中 b | N 且 b >= N^beta。

    f_coeffs 为从低到高的整系数；若首项在模 N 下不可逆则直接放弃。
    返回候选整数根列表（已按 mod 条件校验）。
    """
    f = _poly_from_coeffs(list(f_coeffs))
    delta = len(f) - 1
    if delta <= 0:
        return []
    if beta <= 0 or beta > 1:
        raise ValueError("beta 必须在 (0,1]")

    # 首一化：f -> lc^-1 * f (mod N)
    lc = f[-1] % N
    iv = U.inv(lc, N)
    if iv is None:
        # 首项与 N 不互素，本身就是个因子线索，交给上层
        return []
    f = [(c * iv) % N for c in f]

    if epsilon is None:
        # 已知 X 时按"刚好覆盖"自适应收紧 epsilon，能把维度压到最小、快数倍
        if X is not None and X > 1:
            margin = beta ** 2 / delta - math.log(X) / math.log(N)
            if margin <= 1e-6:
                return []          # 根的上界超出 Coppersmith 可行域
            epsilon = margin * 0.9
        else:
            epsilon = beta / 8
    if m is None:
        m = max(1, int(math.ceil(beta ** 2 / (delta * epsilon))))
    if t is None:
        t = max(0, int(math.floor(delta * m * (1.0 / beta - 1))))

    if X is None:
        X = int(round(gmpy2.mpfr(N) ** (beta ** 2 / delta - epsilon)))
        X = max(X, 2)
    X = int(X)
    if X < 2:
        return []

    dim = delta * m + t
    if dim > 60:
        return []

    # 构造基：N^(m-i) * x^j * f^i  (0<=i<m, 0<=j<delta) 以及 x^i * f^m
    polys: List[List[int]] = []
    fpow = [1]
    for i in range(m):
        for j in range(delta):
            polys.append(_poly_shift(fpow[:], j))
        fpow = _poly_mul(fpow, f)

    fpow_m = fpow[:]
    for i in range(t):
        polys.append(_poly_shift(fpow_m[:], i))

    # 乘上 N 的幂次
    basis: Matrix = []
    idx = 0
    for i in range(m):
        Ni = N ** (m - i)
        for j in range(delta):
            p = polys[idx]
            idx += 1
            row = [0] * dim
            for d, c in enumerate(p):
                if d < dim:
                    row[d] = c * Ni
            basis.append(row)
    for i in range(t):
        p = polys[idx]
        idx += 1
        row = [0] * dim
        for d, c in enumerate(p):
            if d < dim:
                row[d] = c
        basis.append(row)

    # 按 X^d 缩放
    for row in basis:
        for d in range(dim):
            if row[d]:
                row[d] *= X ** d

    if verbose:
        print(f"    [coppersmith] delta={delta} beta={beta} m={m} t={t} dim={dim} X~2^{X.bit_length()}")

    red = lll_reduce(basis, delta=0.75)

    found: List[int] = []
    for row in red[: min(len(red), 8)]:
        # 反缩放
        coeffs = []
        ok = True
        for d in range(dim):
            xd = X ** d
            if row[d] % xd != 0:
                ok = False
                break
            coeffs.append(row[d] // xd)
        if not ok:
            continue
        g = 0
        for c in coeffs:
            g = math.gcd(g, abs(c))
        if g > 1:
            coeffs = [c // g for c in coeffs]
        for r in int_roots(coeffs):
            if r in found:
                continue
            # 校验：gcd(f(r), N) 是否给出非平凡因子，或 f(r) ≡ 0 mod N
            v = U.poly_eval_mod(f, r % N, N) if r >= 0 else None
            if v == 0 or (v is not None and U.gcd(v, N) not in (1, N)):
                found.append(r)
                continue
            if r < 0:
                v2 = U.poly_eval_mod(f, r % N, N)
                if v2 == 0 or U.gcd(v2, N) not in (1, N):
                    found.append(r)
    return found


# --------------------------------------------------------------------------
# 便捷封装：已知因子高位 / 已知明文高位
# --------------------------------------------------------------------------
def factor_high_bits(n: int, p_high: int, unknown_bits: int, verbose: bool = False) -> Optional[int]:
    """p = p_high * 2^unknown_bits + x，已知高位，求 p。"""
    shift = 1 << unknown_bits
    # f(x) = p_high*shift + x  (monic)
    roots = coppersmith_univariate([p_high * shift, 1], n, beta=0.5, X=shift, verbose=verbose)
    for r in roots:
        p = p_high * shift + r
        if p > 1 and n % p == 0:
            return p
    return None


def factor_low_bits(n: int, p_low: int, known_bits: int, verbose: bool = False,
                    beta: float = 0.49) -> Optional[int]:
    """已知 p 的低 known_bits 位，用 Coppersmith 补出高位。

    p = x·2^known_bits + p_low，未知部分 x 的位宽由 n 的位宽推出。
    shift 与 X 必须是两个不同的量：shift 由已知位数决定，
    X 由未知位数决定；把二者混用会让多项式描述的是另一个 p。

    beta 取 0.49 而非 0.5：真实因子可能略小于 √n（高位不足），
    用 0.49 能保证「除数 ≥ N^beta」这个前提依然成立，否则边界处会静默失败。
    """
    if known_bits <= 0:
        return None
    pbits = (U.nbit(n) + 1) // 2
    unknown_bits = pbits - known_bits
    if unknown_bits <= 0:
        return None
    shift = 1 << known_bits
    # f(x) = shift*x + p_low ；先化首一：乘以 shift^-1
    iv = U.inv(shift, n)
    if iv is None:
        return None
    coeffs = [(p_low * iv) % n, 1]
    roots = coppersmith_univariate(coeffs, n, beta=beta, X=1 << unknown_bits,
                                   verbose=verbose)
    for r in roots:
        p = r * shift + p_low
        if 1 < p < n and n % p == 0:
            return p
    return None


def message_high_bits(n: int, e: int, c: int, m_high: int, unknown_bits: int = 0,
                      X: Optional[int] = None, already_shifted: bool = False,
                      verbose: bool = False) -> List[int]:
    """已知明文高位，求 m。

    默认语义与题面一致：m_high = m >> unknown_bits，
    即 m = m_high·2^unknown_bits + x，求小根 x。
    already_shifted=True 表示传入的已经是 m_high << unknown_bits。
    """
    if X is None:
        X = 1 << unknown_bits if unknown_bits else None
    base_val = m_high if already_shifted else (m_high << unknown_bits)
    base = [base_val % n, 1]
    poly = [1]
    for _ in range(e):
        poly = [ci % n for ci in U.poly_mul(poly, base)]
    poly[0] = (poly[0] - c) % n
    roots = coppersmith_univariate(poly, n, beta=1.0, X=X, verbose=verbose)
    out = []
    for r in roots:
        m = (base_val + r) % n
        if U.powmod(m, e, n) == c % n:
            out.append(m)
    return out


def stereotyped_message(n: int, e: int, c: int, prefix: bytes = b"", suffix: bytes = b"",
                        unknown_len: int = 0, verbose: bool = False) -> List[int]:
    """已知明文前后缀（stereotyped message），爆破中间未知字节。

    m = pre·2^(8·(unknown+suf_len)) + x·2^(8·suf_len) + suf，求小根 x。
    """
    pre = U.bytes_to_long(prefix) if prefix else 0
    suf = U.bytes_to_long(suffix) if suffix else 0
    shift = 1 << (8 * unknown_len)
    if shift <= 1 or U.nbit(n) < 1:
        return []
    high = pre * (1 << (8 * (unknown_len + len(suffix))))
    low = suf
    X = 1 << (8 * unknown_len)
    # X 必须小于 n^(1/e)，否则 Coppersmith 的可行域不成立，白跑 LLL
    bound, _ = U.iroot(n, e) if e > 0 else (0, False)
    if X >= bound:
        return []
    base = [(high + low) % n, (1 << (8 * len(suffix))) % n]
    poly = [1]
    for _ in range(e):
        poly = [ci % n for ci in U.poly_mul(poly, base)]
    poly[0] = (poly[0] - c) % n
    roots = coppersmith_univariate(poly, n, beta=1.0, X=X, verbose=verbose)
    out = []
    for r in roots:
        m = high + r * (1 << (8 * len(suffix))) + low
        if U.powmod(m, e, n) == c % n:
            out.append(m)
    return out


# --------------------------------------------------------------------------
# 短填充（short pad）：m2 = m1 + δ，δ 未知但很小
# --------------------------------------------------------------------------
def _short_pad_resultant(e: int, c1: int, c2: int, n: int) -> List[int]:
    """在 Z_n[y]/(x^e - c1) 里求 (x+y)^e - c2 与它的结式，得到 y 的多项式。

    y 就是两条明文的差 δ。结式按 x^e ≡ c1 归约后只剩 e+1 项，
    于是 δ 是模 n 下这个小次数多项式的根。
    """
    # 以 x^k (0<=k<e) 为基，构造「乘以 (x+y)^e - c2」的乘法矩阵
    size = e
    mat = [[[0] * (e + 1) for _ in range(size)] for _ in range(size)]
    for col in range(size):
        for x_power in range(e + 1):
            row = (col + x_power) % e
            reduce_by = c1 if col + x_power >= e else 1
            y_power = e - x_power
            mat[row][col][y_power] += math.comb(e, x_power) * reduce_by
            if x_power == 0:
                mat[row][col][0] -= c2

    # 行列式（按 y 的多项式做，系数模 n）
    det = [0]
    for perm in itertools.permutations(range(size)):
        inversions = sum(perm[i] > perm[j] for i in range(size)
                         for j in range(i + 1, size))
        term = [1]
        for row, col in enumerate(perm):
            factor = mat[row][col]
            product = [0] * (len(term) + len(factor) - 1)
            for i, ti in enumerate(term):
                if ti:
                    for j, fj in enumerate(factor):
                        if fj:
                            product[i + j] += ti * fj
            term = product
        if len(det) < len(term):
            det.extend([0] * (len(term) - len(det)))
        sign = -1 if inversions % 2 else 1
        for deg, coef in enumerate(term):
            det[deg] += sign * coef
    # 结式只含 y^e 的倍次幂，约掉一个 y 因子后取模
    return [det[deg * e] % n for deg in range(e + 1)]


def short_pad(n: int, e: int, c1: int, c2: int, verbose: bool = False):
    """短填充攻击，返回 (m1, m2) 或 None。

    δ < n^(1/e²) 时，δ^e 的搜索空间约 n^(1/e)，落在 Coppersmith 可行域内。
    解出 δ^e 后开 e 次方得 δ，再用 Franklin-Reiter 精确求出两条明文。

    上界必须按实际可行域收紧：结式是 e 次多项式，Coppersmith 要求
    X ≤ N^(beta²/delta) = N^(1/e)，而 delta = e 时余量极小，直接从
    N^(1/e) 起步几乎必然失败。这里从一个小得多的初值开始逐级放大，
    每级都真跑一次 LLL —— δ 通常比理论上界小好几个数量级。
    """
    if e < 2 or e > 5:
        return None
    coeffs = _short_pad_resultant(e, c1 % n, c2 % n, n)
    while len(coeffs) > 1 and coeffs[-1] == 0:
        coeffs.pop()
    if len(coeffs) < 2:
        return None

    # 理论上界 X_z = n^(1/e)；实际从小往上放大，避免边界处白跑大格
    top, _ = U.iroot(n, e)
    bits = max(8, int(U.nbit(top) * 0.5))
    top_bits = U.nbit(top)
    while bits <= top_bits:
        x_z = 1 << bits
        roots = coppersmith_univariate(coeffs, n, beta=1.0, X=x_z, verbose=verbose)
        for z in roots:
            delta, exact = U.iroot(z, e)
            if not exact or delta == 0:
                continue
            got = franklin_reiter(n, e, c1, c2, 1, delta)
            if got:
                return got
        if bits >= top_bits:
            break
        bits = min(bits * 2, top_bits)
    return None


def franklin_reiter(n: int, e: int, c1: int, c2: int, a: int, b: int):
    """m2 = a·m1 + b 时求 (m1, m2)。返回 (m1, m2) 或 None。"""
    if n <= 1 or e < 2:
        return None
    p1 = [(-c1) % n] + [0] * (e - 1) + [1]
    base = [b % n, a % n]
    poly = [1]
    for _ in range(e):
        poly = U.poly_mulmod(poly, base, n)
    poly[0] = (poly[0] - c2) % n
    g, _factor = U.poly_gcd_mod(p1, poly, n)
    if not g or len(g) != 2 or not g[1]:
        return None
    m1 = (-g[0] * U.inv(g[1], n)) % n
    m2 = (a * m1 + b) % n
    if U.powmod(m1, e, n) != c1 % n or U.powmod(m2, e, n) != c2 % n:
        return None
    return m1, m2
