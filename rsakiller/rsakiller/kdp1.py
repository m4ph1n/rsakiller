"""Known-divisor Pollard p-1 (kdp1) 自动攻击。

适用形状（原型：19_NestingDoll_CCB）：外层素数 P 满足
    P - 1 = seed_i * (B1-光滑部分)
其中 seed_i 是内层模数 n1 的 512-bit 素因子。朴素 Pollard p-1 永远盖不住
seed_i，但把底数的指数乘上 n1 后，只要 B1 盖住光滑部分即可捕获 P；
B1 逐级抬升时捕获集逐素数增长（4096-bit 四素数模数上表现为
1024/2048/3071/4095-bit 的嵌套位宽窗口，见 scan_bit_bound）。

复用 rsakiller.factor：素数筛（small_primes，带缓存）与 pollard_pm1
（B1 <= 100_000 时直接委托，因为 pollard_pm1 的筛子上限就是 1e5）。
"""
from __future__ import annotations

import bisect
import time
from typing import Dict, List, Optional, Sequence, Tuple

import gmpy2

from . import factor as F

# pollard_pm1 内部筛子硬上限（factor.small_primes(min(B1, 100_000))）
_PM1_SIEVE_CAP = 100_000

DEFAULT_B1_SCHEDULE: Tuple[int, ...] = (10**4, 10**5, 10**6, 5 * 10**6, 2 * 10**7)


def _prod_tree(nums: List[int]) -> int:
    """两两归约连乘，避免逐个乘进超大多精度的 O(n^2) 开销。"""
    if not nums:
        return 1
    vals = [gmpy2.mpz(x) for x in nums]
    while len(vals) > 1:
        nxt = []
        for i in range(0, len(vals) - 1, 2):
            nxt.append(vals[i] * vals[i + 1])
        if len(vals) % 2:
            nxt.append(vals[-1])
        vals = nxt
    return int(vals[0])


def lcm_up_to(B1: int) -> int:
    """E = lcm(1..B1)（即 <=B1 的全部素数幂之积），复用 factor.small_primes 筛。

    注意 factor.small_primes 的缓存可能大于请求的 limit（缓存命中时原样
    返回），这里必须按 B1 截断，否则层级语义会随调用顺序漂移。"""
    primes = F.small_primes(int(B1))
    primes = primes[:bisect.bisect_right(primes, int(B1))]
    parts: List[int] = []
    for p in primes:
        pp = p
        while pp * p <= B1:
            pp *= p
        parts.append(pp)
    return _prod_tree(parts)


def _level_a(n: int, B1: int, exponent_mult: int, base: int) -> Tuple[int, float]:
    """a = base^(lcm(1..B1)*exponent_mult) mod n，返回 (a, 耗时秒)。"""
    t0 = time.time()
    E = lcm_up_to(B1)
    a = gmpy2.powmod(gmpy2.mpz(base), E * exponent_mult, gmpy2.mpz(n))
    return int(a), time.time() - t0


def kdp1_factor(n: int, known_multipliers: Sequence[int],
                B1_schedule: Sequence[int] = DEFAULT_B1_SCHEDULE,
                verbose: bool = False, base: int = 2) -> Optional[int]:
    """known_multipliers: 已知整除 p-1 的因子列表（嵌套内层模数 / 种子积等），
    其乘积记 known_m。对每个 B1：a = pow(base, lcm(1..B1)*known_m, n)，
    g = gcd(a-1, n)；返回第一个非平凡因子（1 < g < n），否则 None。

    B1 <= 100_000 的层级直接复用 factor.pollard_pm1（其筛子上限恰为 1e5，
    语义与本函数一致）；更大的 B1 走 lcm 路径。g == n（全捕获，无法拆分）
    视为该层级失败，继续抬升 B1 没有意义时最终返回 None。
    """
    n = int(n)
    known_m = 1
    for m in known_multipliers:
        known_m *= int(m)

    for B1 in B1_schedule:
        B1 = int(B1)
        t0 = time.time()
        g: Optional[int] = None
        if B1 <= _PM1_SIEVE_CAP:
            g = F.pollard_pm1(n, B1=B1, retries=2, known_m=known_m)
            dt = time.time() - t0
            if verbose:
                print(f"  [kdp1] B1={B1}: pollard_pm1 -> "
                      f"{'bits ' + str(g.bit_length()) if g else 'None'} ({dt:.1f}s)",
                      flush=True)
        else:
            a, dt_lcm = _level_a(n, B1, known_m, base)
            g = int(gmpy2.gcd(a - 1, n))
            dt = time.time() - t0
            if verbose:
                print(f"  [kdp1] B1={B1}: gcd bits={g.bit_length() if g > 1 else 1} "
                      f"({dt:.1f}s, exp {dt_lcm:.1f}s)", flush=True)
        if g is not None and 1 < g < n:
            return g
    return None


def kdp1_levels(n: int, known_multipliers: Sequence[int],
                B1_schedule: Sequence[int], base: int = 2,
                verbose: bool = False) -> List[Tuple[int, int, float]]:
    """对每个 B1 计算 a = base^(lcm(1..B1)*known_m) mod n（不做 gcd 判定），
    返回 [(B1, a, 耗时秒), ...]，供 scan_bit_bound 消费。全部走 lcm 路径。"""
    n = int(n)
    known_m = 1
    for m in known_multipliers:
        known_m *= int(m)
    out: List[Tuple[int, int, float]] = []
    for B1 in B1_schedule:
        a, dt = _level_a(n, int(B1), known_m, base)
        out.append((int(B1), a, dt))
        if verbose:
            print(f"  [kdp1_levels] B1={B1}: a computed ({dt:.1f}s)", flush=True)
    return out


def scan_bit_bound(n: int, a_after_each_B1: Sequence[int],
                   n_windows: int = 4) -> List[Dict]:
    """嵌套位宽窗口判定（镜像 19_NestingDoll 实解的 capture-by-bit-bound）。

    实解在 4096-bit 四素数模数上观察 gcd 位宽落进 1024/2048/3071/4095-bit
    窗口来判断"捕获了几个外层素数"。这里推广：窗口取 n.bit_length() 的
    等分点 [nbits/k, 2*nbits/k, ..., nbits]。对每个 a 计算 g = gcd(a-1, n)，
    归入第一个 >= g.bit_length() 的窗口；g == n 记 'full'。相邻观测的
    嵌套增量 g_i // g_prev 即候选外层素数（记录是否素数）。

    返回每层一个 dict：{'i', 'gcd', 'bits', 'window', 'full', 'ratio',
    'ratio_is_prime'}；'ratio' 仅在相对前一层出现更大捕获时给出。
    """
    n = int(n)
    nbits = n.bit_length()
    base = -(-nbits // n_windows)          # ceil(nbits / n_windows)
    windows = [base * k for k in range(1, n_windows + 1)]
    out: List[Dict] = []
    prev_g = 1
    for i, a in enumerate(a_after_each_B1):
        g = int(gmpy2.gcd(int(a) - 1, n))
        bits = g.bit_length() if g > 1 else 1
        full = (g == n)
        window = None
        if g > 1 and not full:
            for w in windows:
                if bits <= w:
                    window = w
                    break
        obs: Dict = {"i": i, "gcd": g, "bits": bits,
                     "window": window, "full": full}
        if g > prev_g and prev_g > 1 and g % prev_g == 0:
            r = g // prev_g
            obs["ratio"] = r
            obs["ratio_is_prime"] = bool(gmpy2.is_prime(r))
        elif g > 1 and prev_g == 1:
            obs["ratio"] = g
            obs["ratio_is_prime"] = bool(gmpy2.is_prime(g))
        out.append(obs)
        if g > prev_g:
            prev_g = g
    return out
