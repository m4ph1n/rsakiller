"""特殊结构分解：弱点在 n 的代数形状，而不在素因子大小。

这类题用 Pollard rho / ECM 一辈子也分解不出来，只能靠模式识别：

  * n = p^k           —— 素数幂，phi = (p-1)·p^(k-1)
  * n = a² + b²       —— 两平方和表示，Euler 分解
  * Fermat 乘子       —— k·n 的两个因子彼此接近（含 p、q 成小倍数关系）
  * Carmichael 数     —— Miller-Rabin 过程给出 1 的非平凡平方根
  * p+1 光滑          —— Williams p+1
  * 著名整数序列      —— Fibonacci / Lucas / Mersenne / Fermat 数 / 阶乘 / 素数阶乘
  * 3133...37 型素数  —— ekoparty 2015 "rsa 2070" 玩具素数
  * ROCA 结构         —— n 的模小素数结构判定（只做筛查，不做分解）

全部纯 Python（gmpy2），带显式工作量上限，不适合时立刻返回 None。
"""
from __future__ import annotations

import time
from typing import Dict, Iterable, List, Optional, Tuple

from . import utils as U

Pair = Tuple[int, int]


def _split(factor: int, n: int) -> Optional[Pair]:
    """把候选因子规整成 (p, q)，不成立就丢弃。"""
    if factor is None or not (1 < factor < n):
        return None
    q = n // factor
    if q > 1 and factor * q == n:
        return factor, q
    return None


# --------------------------------------------------------------------------
# n = p^k
# --------------------------------------------------------------------------
def prime_power(n: int) -> Optional[Tuple[int, int]]:
    """n 是素数幂时返回 (p, k)，否则 None。

    k 从大到小试：n = p^6 时先命中 k=6，直接拿到底数 p；
    若从小往大试，k=2 会得到 p^3（合数）而被误判为失败。
    """
    if n < 4:
        return None
    for k in range(n.bit_length(), 1, -1):
        root, exact = U.iroot(n, k)
        if not exact or root < 2:
            continue
        if U.is_probable_prime(root):
            return root, k
    return None


# --------------------------------------------------------------------------
# n = a² + b²（Euler 分解）
# --------------------------------------------------------------------------
def euler_two_squares(n: int, max_iter: int = 1 << 22,
                      deadline: Optional[float] = None) -> Optional[Pair]:
    """p、q 都是 4k+1 型时，n 有两种平方和表示，混合后取 gcd 即得因子。

    求平方和表示只能线性扫描 a ∈ [0, √n)，代价 O(√n)，所以本方法只对
    位数很少的玩具模数有意义；调用方需先按位宽设限，否则纯属浪费预算。
    (a, b) 与 (b, a) 是同一表示，扫描时必须按无序对去重，
    否则会把同一个表示当成两个，混合组合退化成 gcd = n 而漏解。
    """
    if n % 4 != 1:
        return None
    end = U.isqrt(n)
    limit = min(end, max_iter)
    reps: List[Tuple[int, int]] = []
    seen = set()
    for a in range(limit + 1):
        if deadline and time.time() > deadline:
            return None
        b2 = n - a * a
        if b2 < 0:
            break
        b = U.isqrt(b2)
        if b * b != b2 or b == 0:
            continue
        key = (min(a, b), max(a, b))
        if key in seen:
            continue
        seen.add(key)
        reps.append((a, b))
        if len(reps) == 2:
            break
    if limit < end:
        return None          # 没扫完 √n，即使找到两个表示也不敢断言
    if len(reps) < 2:
        return None

    (x1, y1), (x2, y2) = reps[0], reps[1]
    # n | x1²+y1² 且 n | x2²+y2² 时，两种表示的四种混合组合必被某个素因子整除
    combos = (
        x1 * x2 + y1 * y2,
        x1 * x2 - y1 * y2,
        x1 * y2 + x2 * y1,
        x1 * y2 - x2 * y1,
    )
    for value in combos:
        if value:
            got = _split(U.gcd(value, n), n)
            if got:
                return got
    return None


# --------------------------------------------------------------------------
# Fermat 乘子：给 n 乘上小系数，让本来不接近的两个因子变得接近
# --------------------------------------------------------------------------
def fermat_multiplier(n: int, ks: Iterable[int] = (1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31),
                      max_iter: int = 200_000,
                      deadline: Optional[float] = None) -> Optional[Pair]:
    """Fermat 乘子法。

    p、q 本身不接近时，取 k 使 k·n 的两个因子彼此靠近，仍是标准 Fermat。
    Fermat 要求两个因子同为奇数，而 n 本身是奇数，直接对 n 取乘子即可。

    命中后对两个因子分别与 n 取 gcd，直接还原 p、q。
    """
    from . import factor as F

    if n < 4 or n % 2 == 0:
        return None
    for k in ks:
        m = k * n
        if deadline and time.time() > deadline:
            return None
        p = F.fermat(m, max_iter=max_iter)
        if not p:
            continue
        for f in (p, m // p):
            got = _split(U.gcd(f, n), n)
            if got:
                return got
    return None



# --------------------------------------------------------------------------
# Carmichael 数 / 强伪素数：Miller-Rabin 里出现 1 的非平凡平方根
# --------------------------------------------------------------------------
def strong_pseudoprime(n: int, max_bases: int = 64) -> Optional[Pair]:
    """Carmichael 数 / 强伪素数：在 Miller-Rabin 的平方链上找到 1 的非平凡平方根。

    对 Carmichael 数，几乎所有互素基都满足 a^(n-1) ≡ 1，真正的信息来自
    平方链上某个 b 满足 b² ≡ 1 而 b ≢ ±1：此时 gcd(b−1, n) 是 n 的真因子。

    返回的是一对**互补因子**（乘积恰为 n），不保证各自是素数 —— n 有多个
    素因子时（Carmichael 数几乎总是如此），调用方必须把这对因子继续
    分解到素数才能算出正确的 phi。配对交给 factor_from_hint()。
    """
    if n < 9 or n % 2 == 0:
        return None
    f = n - 1
    e = 0
    while f & 1 == 0:
        f >>= 1
        e += 1
    a = 2
    for _ in range(max_bases):
        if a >= n - 1:
            break
        cur = U.powmod(a, f, n)
        for _level in range(e):
            squared = U.powmod(cur, 2, n)
            if squared == 1 and cur not in (1, n - 1):
                got = _split(U.gcd(cur - 1, n), n) or _split(U.gcd(cur + 1, n), n)
                if got:
                    return got
            cur = squared
            if cur == 1:
                break
        a = _next_prime(a + 1)
    return None


def complete_factorization(n: int, timeout: float = 10.0,
                           deadline: Optional[float] = None) -> Optional[Dict[int, int]]:
    """把 n 完整拆成素因子（含指数），拆不干净返回 None。

    特殊结构攻击拿到的往往只是「一对互补因子」，其中每个都可能是合数；
    只有完整素数分解才能算出正确的 phi，进而得到可用的 d。
    """
    from . import utils as U

    if n <= 1:
        return {}
    limit_ = deadline if deadline is not None else (time.time() + timeout)
    stack = [n]
    fac: Dict[int, int] = {}
    while stack:
        cur = stack.pop()
        if cur <= 1:
            continue
        if U.is_probable_prime(cur):
            fac[cur] = fac.get(cur, 0) + 1
            continue
        sub = _split_composite(cur)
        if not sub:
            r = U.isqrt(cur)
            if r * r == cur:
                sub = (r, r)
        if not sub:
            return None
        stack.extend(sub)
    prod = 1
    for p, k in fac.items():
        prod *= p ** k
    if prod != n:
        return None
    return fac


def factor_from_hint(n: int, hint_pair: Pair, timeout: float = 10.0) -> Optional[Dict[int, int]]:
    """把「一对互补因子」扩成 phi 可用的分解字典。

    先尝试完整素数分解；拆不动时退回「以这对因子为原子」的分解 ——
    只要两个因子互素，phi = ∏(g−1) 对它们同样成立，d 也就能算出来。
    这就是 p、q 本身就是「Fibonacci 素数 × 随机素数」这类构造的解法。
    """
    return factor_pair(n, hint_pair, timeout=timeout)


def factor_pair(n: int, pair: Pair, timeout: float = 10.0,
                deadline: Optional[float] = None) -> Optional[Dict[int, int]]:
    """用一对互补因子构造分解字典，优先给出完整的素数分解。

    完整素数分解是 phi 最可靠的形式；但把因子再拆开需要真分解，
    很多题（p 是大 Fibonacci 数、q 是随机素数）本就拆不动。
    这时若两个因子互素，(n) = ∏(g−1)·g^(k−1) 的欧拉函数公式对它们
    仍然成立，直接用 {g: 1} 作为分解即可。
    """
    from . import utils as U

    fac = complete_factorization(n, timeout=timeout, deadline=deadline)
    if fac:
        return fac
    p, q = pair
    if p * q != n or p <= 1 or q <= 1:
        return None
    if U.gcd(p, q) != 1:
        return None
    return {p: 1, q: 1}


def _split_composite(m: int) -> Optional[Pair]:
    """对一个合数做快速拆分（试除 + 短时 Pollard rho），失败返回 None。

    rho 对 60 bit 以上的因子基本无望，所以超时必须短：这里的目的只是
    把「因子里还藏着的小因子」剥出来，不是通用分解。
    """
    from . import factor as F

    d = F.trial_division(m, 200_000)
    if d is None:
        d = F.pollard_rho(m, timeout=1.0)
    if d and 1 < d < m:
        return d, m // d
    return None


def _next_prime(v: int) -> int:
    if v <= 2:
        return 2
    if v % 2 == 0:
        v += 1
    while not U.is_probable_prime(v):
        v += 2
    return v


# --------------------------------------------------------------------------
# Williams p+1
# --------------------------------------------------------------------------
def _mlucas(v: int, a: int, n: int) -> int:
    """Lucas 序列 V_{m·a}(v) mod n（MSB 二进制链）。"""
    v1, v2 = v, (v * v - 2) % n
    for bit in bin(a)[3:]:
        if bit == "0":
            v1, v2 = (v1 * v1 - 2) % n, (v1 * v2 - v) % n
        else:
            v1, v2 = (v1 * v2 - v) % n, (v2 * v2 - 2) % n
    return v1


def williams_pp1(n: int, b1: int = 100_000, seeds: int = 8,
                 deadline: Optional[float] = None) -> Optional[int]:
    """p+1 光滑而 p-1 不光滑时唯一有效的经典方法。"""
    if n % 2 == 0:
        return 2
    primes = _primes_upto(b1)
    for seed in range(1, seeds + 1):
        v = seed
        for p in primes:
            e = 0
            pe = p
            while pe <= b1:
                pe *= p
                e += 1
            for _ in range(max(e, 1)):
                v = _mlucas(v, p, n)
            g = U.gcd(v - 2, n)
            if 1 < g < n:
                return g
            if g == n:
                break
        if deadline and time.time() > deadline:
            return None
    return None


def _primes_upto(limit: int) -> List[int]:
    from .factor import small_primes

    return small_primes(min(limit, 1_000_000))


# --------------------------------------------------------------------------
# 著名整数序列的 gcd
# --------------------------------------------------------------------------
def sequence_gcd(n: int, limit: int = 20_000,
                 deadline: Optional[float] = None) -> Optional[Pair]:
    """题目把 p、q 取成 Fibonacci / Lucas / 阶乘 / 素数阶乘等构造。

    各序列都按 mod n 递推，不会产生巨型整数；命中即返回。
    """
    primes = set(_primes_upto(limit + 1))
    fib0, fib1 = 0, 1
    luc0, luc1 = 2, 1          # L0=2, L1=1
    fact = 1
    primorial = 1
    comp = 1
    bits = n.bit_length()
    for i in range(1, limit + 1):
        if deadline and time.time() > deadline:
            return None
        fib0, fib1 = fib1, (fib0 + fib1) % n
        luc0, luc1 = luc1, (luc0 + luc1) % n
        for value in (fib1, luc1):
            got = _split(U.gcd(value, n), n)
            if got:
                return got
        if i <= bits:
            mersenne = U.powmod(2, i, n) - 1
            got = _split(U.gcd(mersenne, n), n) or _split(U.gcd(mersenne + 2, n), n)
            if got:
                return got
            if i <= 20:
                got = _split(U.gcd(U.powmod(2, 1 << i, n) + 1, n), n)
                if got:
                    return got
        fact = fact * i % n
        got = _split(U.gcd(fact - 1, n), n) or _split(U.gcd(fact + 1, n), n)
        if got:
            return got
        if i in primes:
            primorial = primorial * i % n
            got = _split(U.gcd(primorial - 1, n), n) or _split(U.gcd(primorial + 1, n), n)
            if got:
                return got
        else:
            comp = comp * i % n
            got = _split(U.gcd(comp - 1, n), n) or _split(U.gcd(comp + 1, n), n)
            if got:
                return got
    return None


# --------------------------------------------------------------------------
# 3133…37 型玩具素数（ekoparty 2015 rsa 2070）
# --------------------------------------------------------------------------
def novelty_prime(n: int, max_len: int = 25) -> Optional[int]:
    """形如 3133…37 的素数，位数从头往长试，位数不够就停。"""
    digits = len(str(n))
    for i in range(max(0, max_len - 4)):
        s = "3133" + "3" * i + "7"
        if len(s) > digits:
            break
        cand = int(s)
        if n % cand == 0 and cand > 1:
            return cand
    return None


# --------------------------------------------------------------------------
# ROCA（CVE-2017-15361）：n 落在 65537 的已知小群结构上
# --------------------------------------------------------------------------
# 每个 (小素数, 可接受余数集合) 对：真 ROCA 密钥必须全部落进集合里。
# 只要有一个不等式成立，就能断言「不是 ROCA」，所以这是个便宜的前置筛。
_ROCA_TESTS = [
    (11, {1, 10}),
    (13, {1, 3, 4, 9, 10, 12}),
    (17, {1, 2, 4, 8, 9, 13, 15, 16}),
    (19, {1, 4, 5, 6, 7, 9, 11, 16, 17}),
    (37, {1, 10, 26}),
    (53, {
        1, 4, 6, 7, 9, 10, 11, 13, 15, 16, 17, 24, 25, 28, 29, 36, 37, 38,
        40, 42, 43, 44, 46, 47, 49, 52,
    }),
    (61, {
        1, 3, 8, 9, 11, 20, 23, 24, 27, 28, 33, 34, 37, 38, 41, 50, 52, 53,
        58, 60,
    }),
    (71, {
        1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 15, 16, 18, 19, 20, 24, 25, 27, 29,
        30, 32, 36, 37, 38, 40, 43, 45, 48, 49, 50, 54, 57, 58, 60, 64,
    }),
    (73, {
        1, 3, 7, 8, 9, 10, 17, 21, 22, 24, 27, 30, 43, 46, 49, 51, 52, 56,
        63, 64, 65, 66, 70, 72,
    }),
    (79, {1, 8, 10, 18, 21, 22, 38, 46, 52, 62, 64, 65, 67}),
    (97, {1, 35, 36, 61, 62, 96}),
]


def is_roca_vulnerable(n: int) -> bool:
    """判断 n 是否呈现 ROCA 的模小素数结构。

    只是个必要条件筛子：命中不代表一定能分解，但没命中就一定不是 ROCA。
    """
    if n <= 1:
        return False
    for p, allowed in _ROCA_TESTS:
        if n % p not in allowed:
            return False
    return True
