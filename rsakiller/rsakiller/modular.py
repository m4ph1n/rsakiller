"""模意义下开任意次方（AMM）与合数模上的开方。

用于 e 与 phi 不互素（e | p-1）这类"给了 p、q 也解不出 d"的题。
"""
from __future__ import annotations

import itertools
import random
from typing import List, Optional, Sequence

from . import utils as U


def all_nth_roots_mod_prime(a: int, n: int, p: int, max_roots: int = 4096) -> Optional[List[int]]:
    """求 x^n ≡ a (mod p) 的全部解，p 为素数。

    三种可解情形，其余返回 None 交给 Sage：

      * gcd(n, p−1) = 1 —— 直接求逆元。
      * n | p−1 且 gcd(n, (p−1)/n) = 1 —— 经典 AMM：s = (p−1)/n 与 n 互素，
        于是 r = a^(n⁻¹ mod s) 就是一个根，再乘遍 n 次单位根得到全部解。
        这正是 CTF 里 e ‖ p−1（3 | p−1 但 9 ∤ p−1）的常见形态。
      * 上述之外 —— 需要真正的 p−1 分解 + Hensel 提升，此处不实现。

    注意 (p−1) 含 n 的平方以上因子时（如 9 | p−1 而 n = 3），s 与 n 不再
    互素，AMM 的逆元不存在，必须交给 Sage 的 nth_root。
    """
    a %= p
    if a == 0:
        return [0]
    if p == 2:
        return [a]
    if n <= 0:
        return None
    g = U.gcd(n, p - 1)
    if g == 1:
        iv = U.inv(n, p - 1)
        return [pow(a, iv, p)] if iv is not None else None
    if (p - 1) % n:
        return None                        # n 不整除 p−1，不在本实现范围
    if g > max_roots:
        return None                        # n 太大，枚举单位根不现实
    s = (p - 1) // n
    u = U.inv(n, s)
    if u is None:
        return None                        # gcd(n, s) > 1：需要推广的 AMM
    if pow(a, s, p) != 1:
        return []                          # 不是 n 次剩余，无解
    r = pow(a, u, p)
    if pow(r, n, p) != a:
        return None
    # n 次单位根：s 阶子群里的非平凡生成元，其 n 次方恰为 1
    w = None
    for _ in range(200):
        z = random.randrange(2, p - 1)
        zeta = pow(z, s, p)
        if zeta != 1:
            w = zeta
            break
    if w is None:
        return [r]
    roots = [r]
    cur = 1
    for _ in range(n - 1):
        cur = cur * w % p
        cand = r * cur % p
        if pow(cand, n, p) == a and cand not in roots:
            roots.append(cand)
        if len(roots) > max_roots:
            break
    return roots


def roots_mod_composite(a: int, n_exp: int, p: int, q: int,
                        max_total: int = 8192) -> Optional[List[int]]:
    """求 x^n_exp ≡ a (mod p*q) 的全部解。"""
    return roots_mod_primes(a, n_exp, [p, q], max_total=max_total)


def roots_mod_primes(a: int, n_exp: int, primes: Sequence[int],
                     max_total: int = 8192) -> Optional[List[int]]:
    """求 x^n_exp ≡ a (mod ∏primes) 的全部解。

    逐素数求根再 CRT 组合，支持任意个两两互素的模数（多素因子 RSA）。
    只要有一个素数的求根走不通就返回 None —— 这时调用方应把整批任务交给
    Sage，而不是拿残缺的根集去组合（那会漏掉真正的那组解）。
    """
    per = []
    for p in primes:
        r = all_nth_roots_mod_prime(a, n_exp, p, max_roots=max_total)
        if r is None:
            return None
        if not r:
            return []
        per.append((p, r))

    out: List[int] = []
    for combo in itertools.product(*[r for _, r in per]):
        m, _ = U.crt(list(zip(combo, [p for p, _ in per])))
        if m is not None and m not in out:
            out.append(m)
            if len(out) > max_total:
                return out
    return out
