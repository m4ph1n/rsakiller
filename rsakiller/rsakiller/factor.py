"""整数分解引擎。

策略：小素数试除 -> Fermat(近因子) -> Pollard p-1 -> Pollard rho(Brent)
     -> 在线 FactorDB 兜底，全部带时限。
"""
from __future__ import annotations

import math
import random
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

import gmpy2

from . import utils as U

_SMALL_PRIMES: List[int] = []


def small_primes(limit: int = 1_000_000) -> List[int]:
    global _SMALL_PRIMES
    if _SMALL_PRIMES and _SMALL_PRIMES[-1] >= limit:
        return _SMALL_PRIMES
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
    _SMALL_PRIMES = [i for i in range(limit + 1) if sieve[i]]
    return _SMALL_PRIMES


def trial_division(n: int, limit: int = 1_000_000) -> Optional[int]:
    for p in small_primes(limit):
        if p * p > n:
            return None
        if n % p == 0:
            return p
    return None


def fermat(n: int, max_iter: int = 1_000_000) -> Optional[int]:
    """p、q 很接近时（|p-q| 小）秒解。"""
    if n % 2 == 0:
        return 2
    a = U.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        if b2 >= 0:
            b = U.isqrt(b2)
            if b * b == b2:
                p = a - b
                if 1 < p < n:
                    return p
        a += 1
    return None


def pollard_pm1(n: int, B1: int = 100_000, retries: int = 3,
                known_m: int = 1) -> Optional[int]:
    """Pollard p-1。known_m 是已知能整除某个 p-1 的因子（如题面给的 g/n1），
    将其乘进指数可大幅扩大可破解的 p-1 形状（含一个大已知因子也 OK）。"""
    if n % 2 == 0:
        return 2
    for attempt in range(retries):
        a = 2 + attempt * 3
        for p in small_primes(min(B1, 100_000)):
            e = int(math.log(B1) / math.log(p))
            a = U.powmod(a, p ** max(e, 1), n)
        if known_m > 1:
            a = U.powmod(a, known_m, n)
        g = U.gcd(a - 1, n)
        if 1 < g < n:
            return g
    return None


def _brent(n: int, c: int, deadline: float) -> Optional[int]:
    if n % 2 == 0:
        return 2
    y, m = random.randrange(1, n), 128
    g = r = q = 1
    x = ys = y
    while g == 1:
        x = y
        for _ in range(r):
            y = (y * y + c) % n
        k = 0
        while k < r and g == 1:
            ys = y
            for _ in range(min(m, r - k)):
                y = (y * y + c) % n
                q = q * abs(x - y) % n
            g = U.gcd(q, n)
            k += m
            if time.time() > deadline:
                return None
        r *= 2
    if g == n:
        while True:
            ys = (ys * ys + c) % n
            g = U.gcd(abs(x - ys), n)
            if g > 1:
                break
            if time.time() > deadline:
                return None
    return g if g != n else None


def pollard_rho(n: int, timeout: float = 20.0) -> Optional[int]:
    if n % 2 == 0:
        return 2
    if U.is_probable_prime(n):
        return None
    deadline = time.time() + timeout
    for c in (1, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        g = _brent(n, c, deadline)
        if g and 1 < g < n:
            return g
        if time.time() > deadline:
            return None
    return None


def factordb(n: int, timeout: float = 15.0) -> List[int]:
    """查在线 FactorDB，返回已知素因子列表（可能不全）。"""
    try:
        url = "http://factordb.com/api?query=" + urllib.parse.quote(str(n))
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            import json

            data = json.loads(resp.read().decode())
        if data.get("status") not in ("FF", "CF", "P", "PRP"):
            return []
        out: List[int] = []
        for base, exp in data.get("factors", []):
            out.extend([int(base)] * int(exp))
        return out
    except Exception:
        return []


def sage_factor(n: int, timeout: float = 120.0) -> Dict[int, int]:
    """用 Sage 的 PARI/ECM 分解。

    纯 Python 的 Pollard rho 对 60 bit 以上的因子基本无望，而 Sage 的
    ECM 在几十秒内就能吃掉这种规模。不可用时返回空字典。
    """
    from . import sagebridge as SB

    if not SB.available():
        return {}
    res = SB.run_jobs([{"op": "factor", "n": str(n)}], timeout=timeout)
    if not res or not res[0].get("ok"):
        return {}
    fac: Dict[int, int] = {}
    for base, exp in res[0].get("factors") or []:
        fac[int(base)] = fac.get(int(base), 0) + int(exp)
    prod = 1
    for p, k in fac.items():
        prod *= p ** k
    if prod != int(n):
        return {}
    return fac


def factor(n: int, timeout: float = 30.0, use_online: bool = True,
           verbose: bool = False, use_sage: bool = False) -> Dict[int, int]:
    """完整分解，返回 {素因子: 指数}。分不干净时把剩余合数也放进去。"""
    n = int(n)
    if n <= 1:
        return {}
    fac: Dict[int, int] = {}
    deadline = time.time() + timeout

    def add(x: int) -> None:
        if x <= 1:
            return
        fac[x] = fac.get(x, 0) + 1

    # 1. 试除
    for p in small_primes(100_000):
        if p * p > n:
            break
        while n % p == 0:
            add(p)
            n //= p

    if n == 1:
        return fac

    # 2. 各种算法轮流上
    stack = [n]
    while stack and time.time() < deadline:
        cur = stack.pop()
        if cur == 1:
            continue
        if U.is_probable_prime(cur):
            add(cur)
            continue

        d = None
        # 完全平方数
        r = U.isqrt(cur)
        if r * r == cur:
            stack.extend([r, r])
            continue
        d = fermat(cur, max_iter=200_000)
        if d is None and time.time() < deadline:
            d = pollard_pm1(cur, B1=100_000)
        if d is None and time.time() < deadline:
            d = pollard_rho(cur, timeout=min(15.0, max(1.0, deadline - time.time())))
        if d and 1 < d < cur:
            stack.extend([d, cur // d])
        else:
            add(cur)

    # 3. 在线兜底
    remaining = [x for x in fac if not U.is_probable_prime(x)]

    # 4. Sage ECM：纯 Python 方法对 >60 bit 的因子基本无望
    if remaining and use_sage:
        for comp in remaining:
            got = sage_factor(comp, timeout=min(180.0, max(30.0, timeout * 3)))
            if not got:
                continue
            del fac[comp]
            for g, k in got.items():
                fac[g] = fac.get(g, 0) + k
        remaining = [x for x in fac if not U.is_probable_prime(x)]

    if remaining and use_online:
        for comp in remaining:
            got = factordb(comp)
            if not got:
                continue
            prod = 1
            for g in got:
                prod *= g
            if prod != comp:
                continue
            del fac[comp]
            for g in got:
                add(g)

    if verbose:
        print(f"    [factor] -> { {k: v for k, v in fac.items()} }")
    return fac


def factor_to_pair(n: int, timeout: float = 30.0, use_online: bool = True) -> Optional[tuple]:
    """把 n 拆成两个因子 (p, q)，要求都 > 1。"""
    fac = factor(n, timeout=timeout, use_online=use_online)
    if not fac:
        return None
    primes: List[int] = []
    for p, e in fac.items():
        primes.extend([p] * e)
    if len(primes) == 1:
        return None
    primes.sort()
    # 最常见：两个大素数
    if len(primes) == 2:
        return primes[0], primes[1]
    # 多因子：取一个因子与其余乘积
    p = primes[0]
    q = n // p
    return p, q


def batch_gcd(nums: List[int]) -> List[tuple]:
    """两两 gcd，找出共享素因子的模数对。"""
    out = []
    for i in range(len(nums)):
        for j in range(i + 1, len(nums)):
            g = U.gcd(nums[i], nums[j])
            if 1 < g < min(nums[i], nums[j]):
                out.append((i, j, g))
    return out
