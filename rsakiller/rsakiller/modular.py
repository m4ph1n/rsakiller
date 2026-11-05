"""模意义下开任意次方（AMM）与合数模上的开方。

用于 e 与 phi 不互素（e | p-1）这类"给了 p、q 也解不出 d"的题。
"""
from __future__ import annotations

import random
from typing import List, Optional

from . import utils as U


def all_nth_roots_mod_prime(a: int, n: int, p: int, max_roots: int = 4096) -> Optional[List[int]]:
    """求 x^n ≡ a (mod p) 的全部解。

    支持 gcd(n, p-1) > 1 的常见情形（n || p-1）。返回 None 表示当前实现不支持。
    """
    a %= p
    if a == 0:
        return [0]
    if p == 2:
        return [a]
    g = U.gcd(n, p - 1)
    if g == 1:
        iv = U.inv(n, p - 1)
        return [pow(a, iv, p)] if iv is not None else None
    if (p - 1) % (n * n) == 0 or (p - 1) % (g * g) == 0:
        # n^2 | p-1：需要 Hensel 提升，超出本实现范围
        return None
    s = (p - 1) // n
    if pow(a, s, p) != 1:
        return []  # 不是 n 次剩余，无解
    u = U.inv(n, s)
    if u is None:
        return None
    r = pow(a, u, p)
    if pow(r, n, p) != a:
        return None
    # n 次单位根
    w = None
    for _ in range(200):
        z = random.randrange(2, p - 1)
        zeta = pow(z, s, p)
        if zeta != 1:
            w = zeta
            break
    roots = [r]
    if w is not None:
        cur = 1
        for _ in range(n - 1):
            cur = cur * w % p
            roots.append(r * cur % p)
            if len(roots) > max_roots:
                break
    return roots


def roots_mod_composite(a: int, n_exp: int, p: int, q: int,
                        max_total: int = 8192) -> Optional[List[int]]:
    """求 x^n_exp ≡ a (mod p*q) 的全部解。"""
    rp = all_nth_roots_mod_prime(a, n_exp, p, max_roots=max_total)
    rq = all_nth_roots_mod_prime(a, n_exp, q, max_roots=max_total)
    if not rp or not rq:
        return None
    out: List[int] = []
    for x in rp:
        for y in rq:
            m = U.crt([(x, p), (y, q)])[0]
            if m is not None and m not in out:
                out.append(m)
                if len(out) > max_total:
                    return out
    return out
