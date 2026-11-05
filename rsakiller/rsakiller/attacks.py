"""RSA 攻击库。

每个攻击是一个 (name, 适用性判断, 执行函数) 三元组，
执行函数返回 Result 或 None（表示不适用/未成功）。
"""
from __future__ import annotations

import itertools
import math
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import factor as F
from . import lll as L
from . import modular as M
from . import utils as U
from .ctx import RSAContext


@dataclass
class Result:
    attack: str
    m: Optional[int] = None
    detail: str = ""
    factors: Dict[int, int] = field(default_factory=dict)
    candidates: List[int] = field(default_factory=list)

    def text(self) -> Optional[bytes]:
        if self.m is None:
            return None
        return U.guess_text(self.m)


# --------------------------------------------------------------------------
# 公共辅助
# --------------------------------------------------------------------------
def _flag_like(m: int, n: Optional[int] = None) -> bool:
    if m is None:
        return False
    if n and m >= n:
        m %= n
    b = U.guess_text(m)
    if b is None:
        return False
    return True


def _score(m: int) -> float:
    b = U.guess_text(m)
    if b is None:
        return 0.0
    s = U.printable_ratio(b)
    if b"{" in b and b"}" in b:
        s += 2.0
    if b.startswith(b"flag") or b.startswith(b"ctf") or b.startswith(b"FLAG"):
        s += 0.5
    return s


def best_of(cands: Sequence[int]) -> Optional[int]:
    """从一堆候选明文里挑最像 flag 的。"""
    best, bs = None, 0.0
    for m in cands:
        s = _score(m)
        if s > bs:
            best, bs = m, s
    return best


def _sage_nth_roots(a: int, e: int, p: int, q: int) -> Optional[List[int]]:
    """纯 Python AMM 不支持时（如 9 | p-1），交给 Sage 的 nth_root。"""
    from . import sagebridge as SB

    if not _SAGE_ENABLED or not SB.available():
        return None
    res = SB.run_jobs([
        {"op": "nth_root", "p": str(p), "e": e, "a": str(a)},
        {"op": "nth_root", "p": str(q), "e": e, "a": str(a)},
    ], timeout=120)
    if not res or len(res) < 2 or not res[0].get("ok") or not res[1].get("ok"):
        return None
    rp = [int(x) for x in res[0]["values"]]
    rq = [int(x) for x in res[1]["values"]]
    out: List[int] = []
    for x in rp:
        for y in rq:
            m = U.crt([(x, p), (y, q)])[0]
            if m is not None and m not in out:
                out.append(m)
    return out


def decrypt_from_factors(ctx: RSAContext, fac: Dict[int, int]) -> Optional[Result]:
    """已知完整分解 -> 解 d -> 解密。含多素因子与 gcd(e,phi)!=1 的情况。"""
    if not fac or ctx.c is None:
        return None
    n, e, c = ctx.n, ctx.e, ctx.c
    prod = 1
    for p, k in fac.items():
        prod *= p ** k
    if prod != n:
        return None
    phi = 1
    for p, k in fac.items():
        phi *= (p - 1) * p ** (k - 1)
    d = U.inv(e, phi)
    if d is not None:
        m = U.powmod(c, d, n)
        if U.powmod(m, e, n) == c % n:
            return Result("decrypt", m, f"d = inv(e, phi)，phi 有 {phi.bit_length()} bit", dict(fac))
        return None
    # e 与 phi 不互素：剥离公有因子 g = gcd(e, phi)
    # 先求 g 次根，再用 e/g 的逆元解密。直接开 e 次方在 e 很大时不可行。
    g = U.gcd(e, phi)
    if g <= 1:
        return None
    e1 = e // g
    if U.gcd(e1, phi) != 1:
        return None
    d1 = U.inv(e1, phi)
    if d1 is None:
        return None
    primes = sorted(fac.keys())
    if len(primes) != 2:
        return None
    if g > (1 << 20):
        return None            # 公有因子太大，开根不现实
    roots = M.roots_mod_composite(c, g, primes[0], primes[1])
    if roots is None:
        # 纯 Python 的 AMM 只支持 n || p-1，其余情形交给 Sage
        roots = _sage_nth_roots(c, g, primes[0], primes[1])
    if not roots:
        return None
    cands = []
    for y in roots:
        m = U.powmod(y, d1, n)
        if U.powmod(m, e, n) == c % n and m not in cands:
            cands.append(m)
    if not cands:
        return None
    m = best_of(cands)
    return Result("decrypt(e|phi 剥离因子)", m,
                  f"g=gcd(e,phi)={g}，求 {g} 次根后用 e/g 解密，{len(cands)} 个候选",
                  dict(fac), cands)


# --------------------------------------------------------------------------
# 1. 已知 p/q/d
# --------------------------------------------------------------------------
def attack_known_pq(ctx: RSAContext, opts) -> Optional[Result]:
    if ctx.p and ctx.q and ctx.n and ctx.p * ctx.q == ctx.n:
        return decrypt_from_factors(ctx, {ctx.p: 1, ctx.q: 1})
    if ctx.p and ctx.n and ctx.n % ctx.p == 0:
        return decrypt_from_factors(ctx, {ctx.p: 1, ctx.n // ctx.p: 1})
    if ctx.q and ctx.n and ctx.n % ctx.q == 0:
        return decrypt_from_factors(ctx, {ctx.q: 1, ctx.n // ctx.q: 1})
    return None


def attack_known_d(ctx: RSAContext, opts) -> Optional[Result]:
    if not (ctx.d and ctx.n and ctx.c is not None and ctx.e):
        return None
    m = U.powmod(ctx.c, ctx.d, ctx.n)
    if U.powmod(m, ctx.e, ctx.n) == ctx.c % ctx.n:
        return Result("known_d", m, "题目直接给了私钥 d")
    # d 给错或 c 不是标准密文，仍然返回（可能题目就是让这么解）
    return Result("known_d(未校验)", m, "用给定 d 解密，但 e·d 验证未通过")


def attack_d_factor(ctx: RSAContext, opts) -> Optional[Result]:
    """只知道 d 和 n：e·d-1 = k·phi，枚举小 k 反解 phi -> 分解 n。"""
    if not (ctx.d and ctx.n and not (ctx.p or ctx.q)):
        return None
    n, e, d = ctx.n, ctx.e, ctx.d
    if not e:
        return None
    ed1 = e * d - 1
    for k in range(1, 100000):
        if ed1 % k:
            continue
        phi = ed1 // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = U.isqrt(disc)
        if r * r != disc:
            continue
        p, q = (s + r) // 2, (s - r) // 2
        if p * q == n and p > 1:
            res = decrypt_from_factors(ctx, {p: 1, q: 1})
            if res:
                res.attack = "d_leak"
                res.detail = f"由 e·d-1 = k·phi 枚举 k={k} 分解 n"
                return res
    return None


# --------------------------------------------------------------------------
# 2. dp / dq 泄露（CTF 高频）
# --------------------------------------------------------------------------
def attack_dp_leak(ctx: RSAContext, opts) -> Optional[Result]:
    if not ctx.n or not ctx.e:
        return None
    for name, val in (("dp", ctx.dp), ("dq", ctx.dq)):
        if not val:
            continue
        n, e = ctx.n, ctx.e
        # 技巧一：gcd(2^(e*var) - 2, n) 直接给出一个因子，O(1)
        g = U.gcd(U.powmod(2, e * val, n) - 2, n)
        if 1 < g < n:
            fac = {g: 1, n // g: 1}
            res = decrypt_from_factors(ctx, fac)
            if res:
                res.attack = f"{name}_leak"
                res.detail = f"gcd(2^(e·{name})-2, n) 得到因子"
                return res
        # 技巧二：e*dp-1 = k(p-1)，枚举小 k
        t = e * val - 1
        lim = min(e if e < 10 ** 7 else 10 ** 7, 2_000_000)
        for k in range(1, lim + 1):
            if t % k:
                continue
            p = t // k + 1
            if p > 1 and n % p == 0:
                res = decrypt_from_factors(ctx, {p: 1, n // p: 1})
                if res:
                    res.attack = f"{name}_leak"
                    res.detail = f"e·{name}-1 = k(p-1)，k={k}"
                    return res
    return None


# --------------------------------------------------------------------------
# 3. 分解类
# --------------------------------------------------------------------------
def attack_small_q(ctx: RSAContext, opts) -> Optional[Result]:
    if not ctx.n or U.nbit(ctx.n) > 4096:
        return None
    d = F.trial_division(ctx.n, 1_000_000)
    if d is None:
        return None
    fac = F.factor(ctx.n, timeout=10, use_online=False)
    if len(fac) < 2:
        return None
    res = decrypt_from_factors(ctx, fac)
    if res:
        res.attack = "small_q"
        res.detail = "n 含小于 1e6 的素因子，直接试除"
    return res


def attack_c_share_factor(ctx: RSAContext, opts) -> Optional[Result]:
    """gcd(c, n) != 1 —— 题目的密文本身泄露了因子。"""
    if not ctx.n or ctx.c is None:
        return None
    g = U.gcd(ctx.c, ctx.n)
    if 1 < g < ctx.n:
        res = decrypt_from_factors(ctx, {g: 1, ctx.n // g: 1})
        if res:
            res.attack = "c_gcd_n"
            res.detail = "gcd(c, n) 直接给出因子"
        return res
    return None


def attack_common_factor(ctx: RSAContext, opts) -> Optional[Result]:
    """多个模数共享素因子（批量 GCD），CTF 极高频。"""
    ns = ctx.ns if len(ctx.ns) > 1 else []
    if len(ns) < 2:
        return None
    pairs = F.batch_gcd(ns)
    if not pairs:
        return None
    i, j, g = pairs[0]
    for idx in (i, j):
        n = ns[idx]
        c = ctx.cs[idx] if len(ctx.cs) == len(ns) else ctx.c
        if c is None:
            continue
        sub = RSAContext(n=n, e=ctx.e or (ctx.es[idx] if ctx.es else 65537), c=c)
        res = decrypt_from_factors(sub, {g: 1, n // g: 1})
        if res:
            res.attack = "common_factor"
            res.detail = f"n[{i}] 与 n[{j}] 共享素因子"
            return res
    return None


def attack_fermat(ctx: RSAContext, opts) -> Optional[Result]:
    if not ctx.n or ctx.n % 2 == 0:
        return None
    if U.nbit(ctx.n) > 2048:
        return None
    p = F.fermat(ctx.n, max_iter=500_000)
    if not p:
        return None
    res = decrypt_from_factors(ctx, {p: 1, ctx.n // p: 1})
    if res:
        res.attack = "fermat"
        diff = abs(ctx.n // p - p)
        res.detail = f"p、q 接近，|p-q| ≈ 2^{diff.bit_length()}"
    return res


def attack_generic_factor(ctx: RSAContext, opts) -> Optional[Result]:
    """Pollard rho / p-1 / 平方数 / 素模数 等通用分解。"""
    if not ctx.n:
        return None
    if ctx.p and ctx.q and ctx.p * ctx.q == ctx.n:
        return None            # 已经知道分解，分解类攻击没有意义
    n = ctx.n
    if U.is_probable_prime(n):
        if not (ctx.e and ctx.c is not None):
            return None
        phi = n - 1
        d = U.inv(ctx.e, phi)
        if d is not None:
            m = U.powmod(ctx.c, d, n)
            if U.powmod(m, ctx.e, n) == ctx.c % n:
                return Result("n_prime", m, "n 本身是素数，phi = n-1")
        return None
    timeout = getattr(opts, "factor_timeout", 20)
    fac = F.factor(n, timeout=timeout, use_online=getattr(opts, "online", True))
    if len(fac) < 2 and not any(v > 1 for v in fac.values()):
        return None
    if sum(fac.values()) < 2:
        return None
    res = decrypt_from_factors(ctx, fac)
    if res:
        res.attack = "factorize"
        res.detail = "通用分解（Fermat/Pollard p-1/Pollard rho 组合）"
    return res


def attack_factordb(ctx: RSAContext, opts) -> Optional[Result]:
    if not ctx.n or not getattr(opts, "online", True):
        return None
    if ctx.p and ctx.q and ctx.p * ctx.q == ctx.n:
        return None            # 已经知道分解，不必联网
    if U.nbit(ctx.n) > 1024:
        return None
    got = F.factordb(ctx.n)
    if not got:
        return None
    fac: Dict[int, int] = {}
    for p in got:
        fac[p] = fac.get(p, 0) + 1
    prod = 1
    for p, k in fac.items():
        prod *= p ** k
    if prod != ctx.n:
        return None
    res = decrypt_from_factors(ctx, fac)
    if res:
        res.attack = "factordb"
        res.detail = "在线 FactorDB 查到了完整分解"
    return res


# --------------------------------------------------------------------------
# 4. 低加密指数
# --------------------------------------------------------------------------
def attack_small_e_root(ctx: RSAContext, opts) -> Optional[Result]:
    """c = m^e，m^e 不大：对 c + k*n 开 e 次方。"""
    if not (ctx.n and ctx.e and ctx.c is not None):
        return None
    e = ctx.e
    if e > 32 or e < 2:
        return None
    max_k = getattr(opts, "max_k", 200_000)
    c0 = ctx.c % ctx.n
    for k in range(max_k + 40):
        target = c0 + k * ctx.n
        r, exact = U.iroot(target, e)
        if exact:
            m = r
            if U.powmod(m, e, ctx.n) == c0:
                return Result("small_e_root", m, f"c + {k}·n 开 {e} 次方精确")
        if k > 4 and target.bit_length() > ctx.n.bit_length() + 64:
            break
    return None


def attack_hastad(ctx: RSAContext, opts) -> Optional[Result]:
    """低指数广播攻击：同一明文用 e 个不同模数加密。"""
    triples = ctx.triples
    if not triples:
        # 尝试用 ns/cs 自己拼
        if len(ctx.ns) >= 2 and len(ctx.cs) == len(ctx.ns):
            es = ctx.es if len(ctx.es) == len(ctx.ns) else [ctx.e or 3] * len(ctx.ns)
            triples = list(zip(ctx.ns, es, ctx.cs))
    if len(triples) < 2:
        return None
    # 按 e 分组
    for e in {t[1] for t in triples}:
        group = [t for t in triples if t[1] == e]
        if len(group) < e or len(group) < 2:
            continue
        for combo in itertools.combinations(group, e):
            ns = [t[0] for t in combo]
            cs = [t[2] for t in combo]
            x, mod = U.crt(list(zip(cs, ns)))
            if x is None:
                continue
            r, exact = U.iroot(x, e)
            if exact:
                return Result("hastad", r, f"{e} 组同明文广播，CRT 后开 {e} 次方")
            # 允许 c 稍大：试加 k*mod
            for k in range(1, 2000):
                r2, ex2 = U.iroot(x + k * mod, e)
                if ex2:
                    return Result("hastad", r2, f"{e} 组广播 + k={k}")
    return None


# --------------------------------------------------------------------------
# 5. 共模攻击
# --------------------------------------------------------------------------
def attack_common_modulus(ctx: RSAContext, opts) -> Optional[Result]:
    """同一个 n，两个互素的 e 加密同一个 m。"""
    groups: Dict[int, List[Tuple[int, int]]] = {}
    if ctx.triples:
        for n, e, c in ctx.triples:
            groups.setdefault(n, []).append((e, c))
    if ctx.n and len(ctx.es) == len(ctx.cs) and len(ctx.cs) >= 2:
        groups.setdefault(ctx.n, list(zip(ctx.es, ctx.cs)))

    for n, items in groups.items():
        for (e1, c1), (e2, c2) in itertools.combinations(items, 2):
            if U.gcd(e1, e2) != 1:
                continue
            a, b, g = _ext_gcd(e1, e2)
            if g != 1:
                continue
            m = (_signed_pow(c1, a, n) * _signed_pow(c2, b, n)) % n
            if U.powmod(m, e1, n) == c1 % n:
                return Result("common_modulus", m, f"e1={e1}, e2={e2} 互素，扩展欧几里得")
    return None


def _ext_gcd(a: int, b: int) -> Tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_s, old_t, old_r


def _signed_pow(base: int, exp: int, mod: int) -> int:
    if exp >= 0:
        return U.powmod(base, exp, mod)
    return U.powmod(U.inv(base, mod) or 0, -exp, mod)


# --------------------------------------------------------------------------
# 6. 小私钥 d
# --------------------------------------------------------------------------
def wiener_attack(n: int, e: int) -> Optional[int]:
    for k, d in U.convergents(U.continued_fraction(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = U.isqrt(disc)
        if r * r == disc:
            return d
    return None


def attack_wiener(ctx: RSAContext, opts) -> Optional[Result]:
    if not (ctx.n and ctx.e and ctx.c is not None):
        return None
    d = wiener_attack(ctx.n, ctx.e)
    if d is None:
        return None
    m = U.powmod(ctx.c, d, ctx.n)
    if U.powmod(m, ctx.e, ctx.n) != ctx.c % ctx.n:
        return None
    return Result("wiener", m, f"连分数恢复 d（{d.bit_length()} bit，远小于 n^0.25）")


def _recover_from_power_sum(n: int, k: int, T: int) -> Optional[int]:
    """已知 p^k + q^k ≈ T（误差 < n）且 n = p·q，求 p。

    用 s = p+q 把幂和写成 s 的多项式，整数开方反解，再在附近 ±4 试。
    """
    for ds in range(-4, 5):
        if k == 2:
            v = T + 2 * n
            if v <= 0:
                continue
            s = U.isqrt(v) + ds
        elif k == 4:
            inner = 2 * n * n + T
            if inner < 0:
                continue
            y = 2 * n + U.isqrt(inner)
            if y <= 0:
                continue
            s = U.isqrt(y) + ds
        else:
            return None
        if s <= 0:
            continue
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = U.isqrt(disc)
        if r * r != disc or (s + r) % 2:
            continue
        p, q = (s + r) // 2, (s - r) // 2
        if p > 1 and q > 1 and p * q == n:
            return p
    return None


def attack_approx_power(ctx: RSAContext, opts) -> Optional[Result]:
    """e 由 (p^k-1)(q^k-1)·v/u + w 构造（|w| < v·n，u、v 都很小）。

    此时 e / n^k ≈ v/u，连分数能精确给出 v/u；再反推 A = e·u/v ≈ (p^k-1)(q^k-1)，
    进而得 p^k+q^k = n^k - A + 1，解出 p+q 即可分解 n。
    典型题：e = ((p^4-1)(q^4-1)*v + w) / u。
    """
    if not (ctx.n and ctx.c is not None):
        return None
    n = ctx.n
    # 题面常有 e1/e2/e3 多个指数，且 flag 用的未必是第一个，全部试一遍
    cand_e: List[int] = []
    for ee in [ctx.e] + list(ctx.es or []):
        if ee and ee not in cand_e:
            cand_e.append(ee)
    saved_e = ctx.e
    limit = 1 << 26                       # u、v 的上界（与常见出题范围一致）
    try:
        for e in cand_e:
            if U.nbit(e) < 2 * U.nbit(n) + 32:
                continue                  # e 不够大，不是这种构造
            for k in (4, 2, 3):
                den = n ** k
                if U.nbit(e) > U.nbit(den) + 8:
                    continue
                for num, den2 in U.convergents(U.continued_fraction(e, den)):
                    if not (2 <= num < limit and 2 <= den2 < limit):
                        continue
                    for v, u in ((num, den2), (den2, num)):
                        A = (e * u) // v
                        T = den - A + 1
                        p = _recover_from_power_sum(n, k, T)
                        if p and n % p == 0:
                            ctx.e = e
                            res = decrypt_from_factors(ctx, {p: 1, n // p: 1})
                            ctx.e = saved_e
                            if res:
                                res.attack = "approx_power"
                                res.detail = (f"e ≈ n^{k}·v/u（u={u}, v={v}），"
                                              f"反推 p^{k}+q^{k}")
                                return res
    finally:
        ctx.e = saved_e
    return None


def attack_boneh_durfee(ctx: RSAContext, opts) -> Optional[Result]:
    if not (ctx.n and ctx.e and ctx.c is not None):
        return None
    if not getattr(opts, "boneh_durfee", True):
        return None
    if ctx.e < ctx.n // 2:
        return None  # e 不够大，BD 不适用
    from . import bonedurfee

    d = bonedurfee.attack(ctx.n, ctx.e, timeout=getattr(opts, "bd_timeout", 120))
    if d is None:
        return None
    m = U.powmod(ctx.c, d, ctx.n)
    if U.powmod(m, ctx.e, ctx.n) != ctx.c % ctx.n:
        return None
    return Result("boneh_durfee", m, f"格攻击恢复 d（{d.bit_length()} bit）")


# --------------------------------------------------------------------------
# 7. 部分信息泄露（Coppersmith）
# --------------------------------------------------------------------------
def _unknown_bit_candidates(n: int, hint: int) -> List[int]:
    """根据 hint 的位宽猜"未知位数"。p 约 n 的平方根。"""
    bn = U.nbit(n)
    pbits = (bn + 1) // 2
    base = pbits - U.nbit(hint)
    cands = []
    for delta in (0, 1, -1, 2, -2, 3, -3, 8, -8):
        ub = base + delta
        if 0 < ub < bn // 2:
            cands.append(ub)
    return cands


def _normalize_hint(n: int, hint: int):
    """把各种泄露形式统一成 p = (高位) * 2^k + x 的模型。

    CTF 里常见两种：
      1. hint = p >> k            -> 本身就是高位
      2. hint = (p >> k) << k     -> 低位清零，尾随大量 0
    情形 2 必须先右移掉尾随零，否则会把 2^k 当成一次额外移位，根就错了。
    返回 (高位, 估计的未知位数)。
    """
    pbits = (U.nbit(n) + 1) // 2
    tz = 0
    if hint > 0:
        tz = (hint & -hint).bit_length() - 1
    if tz >= 16:                      # 低位清零形式
        hint = hint >> tz
    ub = pbits - U.nbit(hint)
    return hint, ub


def attack_partial_p(ctx: RSAContext, opts) -> Optional[Result]:
    """已知 p（或 q）的高位 / 低位。"""
    if not ctx.n or not ctx.e or ctx.c is None:
        return None
    hint = ctx.hints.get("hint") or ctx.hints.get("leak")
    if not hint:
        return None
    n = ctx.n
    hint, _ub0 = _normalize_hint(n, hint)
    if U.nbit(hint) >= U.nbit(n) // 2:
        return None  # 位宽不对，大概不是因子高位

    cands: List[int] = [_ub0]          # 尾随零推出的位宽最可靠，优先
    if ctx.leak_shift and ctx.leak_shift != _ub0:
        cands.append(ctx.leak_shift)   # 题面声明的移位量作备选
    cands.extend(_unknown_bit_candidates(n, hint))
    seen = set()
    for ub in cands:
        if ub in seen or ub <= 0 or ub >= U.nbit(n) // 2:
            continue
        seen.add(ub)
        p = L.factor_high_bits(n, hint, ub, verbose=getattr(opts, "verbose", False))
        if p and n % p == 0:
            res = decrypt_from_factors(ctx, {p: 1, n // p: 1})
            if res:
                res.attack = "partial_p_high"
                res.detail = f"已知 p 高位，未知 {ub} bit，Coppersmith 恢复"
                return res
        if ctx.leak_low_bits:
            p = L.factor_low_bits(n, hint, ub, verbose=getattr(opts, "verbose", False))
            if p and n % p == 0:
                res = decrypt_from_factors(ctx, {p: 1, n // p: 1})
                if res:
                    res.attack = "partial_p_low"
                    res.detail = f"已知 p 低位，未知 {ub} bit，Coppersmith 恢复"
                    return res
    return None


def attack_m_high(ctx: RSAContext, opts) -> Optional[Result]:
    """已知明文高位（如 flag 前缀已知）。"""
    if not (ctx.n and ctx.e and ctx.c is not None):
        return None
    hint = ctx.hints.get("m") or ctx.hints.get("hint")
    if not hint or hint >= ctx.n:
        return None
    if ctx.e > 17:
        return None
    cands: List[int] = []
    if getattr(opts, "m_unknown_bits", None):
        cands.append(opts.m_unknown_bits)
    if ctx.leak_shift:
        cands.append(ctx.leak_shift)
    # CTF 里未知部分通常是整字节：8/16/32/64 位，先扫这些常见值
    cands.extend([8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 128])
    cands.extend(_unknown_bit_candidates(ctx.n, hint))
    seen = set()
    for ub in cands:
        if ub in seen or ub <= 0:
            continue
        seen.add(ub)
        ms = L.message_high_bits(ctx.n, ctx.e, ctx.c, hint, ub, verbose=getattr(opts, "verbose", False))
        if ms:
            return Result("m_high", ms[0], f"已知明文高位，未知 {ub} bit")


def attack_stereotyped(ctx: RSAContext, opts) -> Optional[Result]:
    prefix = getattr(opts, "m_prefix", None)
    unknown_len = getattr(opts, "m_unknown_len", 0)
    if prefix is None or not (ctx.n and ctx.e and ctx.c is not None):
        return None
    if ctx.e > 17:
        return None
    pre = prefix.encode() if isinstance(prefix, str) else prefix
    ms = L.stereotyped_message(ctx.n, ctx.e, ctx.c, prefix=pre, unknown_len=unknown_len,
                               verbose=getattr(opts, "verbose", False))
    if ms:
        return Result("stereotyped", ms[0], "已知明文前缀（stereotyped message）")
    return None


# --------------------------------------------------------------------------
# 8. 相关消息（Franklin-Reiter）
# --------------------------------------------------------------------------
def attack_franklin_reiter(ctx: RSAContext, opts) -> Optional[Result]:
    """同 n 同 e，两条明文满足 m2 = a·m1 + b。"""
    if not (ctx.n and ctx.e) or len(ctx.cs) < 2:
        return None
    n, e = ctx.n, ctx.e
    if e > 17:
        return None
    pairs = [(1, 1), (1, -1), (1, 0)]
    rel = getattr(opts, "related", None)
    if rel:
        a, b = rel
        pairs = [(a, b)]
    for a, b in pairs:
        c1, c2 = ctx.cs[0], ctx.cs[1]
        # p1 = x^e - c1 ; p2 = (a x + b)^e - c2
        p1 = [(-c1) % n] + [0] * (e - 1) + [1]
        base = [b % n, a % n]
        poly = [1]
        for _ in range(e):
            poly = U.poly_mulmod(poly, base, n)
        poly[0] = (poly[0] - c2) % n
        g, fac = U.poly_gcd_mod(p1, poly, n)
        if fac:
            res = decrypt_from_factors(ctx, {fac: 1, n // fac: 1})
            if res:
                res.attack = "franklin_reiter(gcd 意外分解)"
                return res
        if not g or len(g) != 2:
            continue
        # g = x + g0  => m1 = -g0
        m1 = (-g[0]) % n
        if U.powmod(m1, e, n) == c1 % n:
            return Result("franklin_reiter", m1, f"相关消息 m2 = {a}·m1 + {b}")
        m1 = (-g[0] * U.inv(g[1], n)) % n if g[1] else None
        if m1 is not None and U.powmod(m1, e, n) == c1 % n:
            return Result("franklin_reiter", m1, f"相关消息 m2 = {a}·m1 + {b}")
    return None


# --------------------------------------------------------------------------
# MT19937：恢复状态 + 重放 RSA 素数生成
# --------------------------------------------------------------------------
def attack_mt_replay(ctx: RSAContext, opts) -> Optional[Result]:
    """题目先打印 getrandbits(大数)，再用小种子重新播种生成 p、q。

    大数 >= 19968 bit 时可直接还原 MT19937 状态，预测种子后重放 getPrime。
    """
    big = ctx.hints.get("mt_output")
    if not big or ctx.c is None:
        return None
    from . import mt19937 as MT

    # 题目脚本里若给了 getPrime(1024)，直接用它，省掉位宽猜测
    pb = ctx.hints.get("prime_bits")
    r = MT.attack(big, ctx.c, pbits=pb if isinstance(pb, int) else None,
                  verbose=getattr(opts, "verbose", False))
    if not r:
        return None
    b, kind, skip = r
    m = int.from_bytes(b, "big")
    return Result("mt19937_replay", m,
                  f"MT19937 状态恢复 → 预测种子 → getPrime 重放（skip={skip}）")


# --------------------------------------------------------------------------
# Sage 重型批量：Coppersmith / Boneh-Durfee 一次进程内跑完
# --------------------------------------------------------------------------
_SAGE_CACHE: Dict[tuple, Optional[Result]] = {}
# 由 solver 按 Options.use_sage 设置；纯 Python 模式必须真的不碰 Sage
_SAGE_ENABLED = True


def _sage_ctx_key(ctx: RSAContext) -> tuple:
    hs = tuple(sorted((str(k), v) for k, v in ctx.hints.items() if isinstance(v, int)))
    return (ctx.n, ctx.e, ctx.c, hs)


def attack_sage_heavy(ctx: RSAContext, opts) -> Optional[Result]:
    """把 Coppersmith（p 高位 / 明文高位）与 Boneh-Durfee 一次性交给 Sage。

    只付一次 Sage 启动成本（本机 Cygwin 版约 20~40 秒），结果按 context 缓存。
    """
    if not (ctx.n and ctx.e and ctx.c is not None):
        return None
    if not getattr(opts, "use_sage", True):
        return None
    from . import sagebridge as SB

    if not SB.available():
        return None
    key = _sage_ctx_key(ctx)
    if key in _SAGE_CACHE:
        return _SAGE_CACHE[key]

    n, e, c = ctx.n, ctx.e, ctx.c
    verbose = getattr(opts, "verbose", False)
    jobs: List[dict] = []
    meta: List[tuple] = []
    p_mode = "high"

    # ---- A. 已知 p 高位 / 低位 ----
    hint = ctx.hints.get("hint") or ctx.hints.get("leak")
    if hint and 0 < hint < n:
        hint, _ub0 = _normalize_hint(n, hint)
    if hint and 0 < hint < n and U.nbit(hint) < U.nbit(n) // 2 + 8:
        cands: List[int] = [_ub0]
        if ctx.leak_shift and ctx.leak_shift != _ub0:
            cands.append(ctx.leak_shift)
        cands.extend(_unknown_bit_candidates(n, hint))
        seen = set()
        picked: List[int] = []
        for ub in cands:
            if ub in seen or ub <= 0 or ub >= U.nbit(n) // 2:
                continue
            seen.add(ub)
            picked.append(ub)
            if len(picked) >= 4:
                break
        p_mode = "low" if ctx.leak_low_bits else "high"
        for ub in picked:
            jobs.append({"op": "partial_p", "n": str(n), "hint": str(hint),
                         "unknown_bits": ub, "mode": p_mode})
            meta.append(("partial_p", ub))

    # ---- B. 已知明文高位（e 必须小） ----
    mh = ctx.hints.get("m")
    if mh is None and e <= 17 and hint and 0 < hint < n:
        mh = hint
    if mh is not None and 0 < mh < n and e <= 17:
        cands = []
        if getattr(opts, "m_unknown_bits", None):
            cands.append(int(opts.m_unknown_bits))
        if ctx.leak_shift:
            cands.append(ctx.leak_shift)
        cands.extend([8, 16, 24, 32, 40, 48, 64, 96])
        seen = set()
        picked = []
        for ub in cands:
            if ub in seen or ub <= 0 or ub > U.nbit(n):
                continue
            seen.add(ub)
            picked.append(ub)
            if len(picked) >= 4:
                break
        for ub in picked:
            jobs.append({"op": "message_high", "n": str(n), "e": e, "c": str(c),
                         "m_high": str(mh), "unknown_bits": ub})
            meta.append(("message_high", ub))

    # ---- C. Boneh-Durfee ----
    if getattr(opts, "boneh_durfee", True) and e > n // 2 and e > 1:
        jobs.append({"op": "boneh_durfee", "n": str(n), "e": str(e),
                     "delta": float(getattr(opts, "bd_delta", 0.26)), "m": 4})
        meta.append(("boneh_durfee", None))

    if not jobs:
        _SAGE_CACHE[key] = None
        return None

    if verbose:
        print("    [sage] 提交 %d 个重型任务（p高位 %d，明文高位 %d，BD %d）" % (
            len(jobs),
            sum(1 for m in meta if m[0] == "partial_p"),
            sum(1 for m in meta if m[0] == "message_high"),
            sum(1 for m in meta if m[0] == "boneh_durfee")))
    results = SB.run_jobs(jobs, timeout=float(getattr(opts, "sage_timeout", 900.0)),
                          verbose=verbose)
    if results is None:
        # Sage 不可用 / 超时：不缓存，留给纯 Python 兜底
        return None

    for (kind, info), r in zip(meta, results):
        if not r or not r.get("ok"):
            continue
        try:
            if kind == "partial_p":
                p = int(r["value"])
                if p > 1 and n % p == 0:
                    res = decrypt_from_factors(ctx, {p: 1, n // p: 1})
                    if res:
                        res.attack = "partial_p_%s(sage)" % p_mode
                        res.detail = f"Sage Coppersmith 恢复因子（未知 {info} bit）"
                        _SAGE_CACHE[key] = res
                        return res
            elif kind == "message_high":
                m = int(r["value"])
                if U.powmod(m, e, n) == c % n:
                    res = Result("m_high(sage)", m, f"Sage small_roots，未知 {info} bit")
                    _SAGE_CACHE[key] = res
                    return res
            elif kind == "boneh_durfee":
                d = int(r["value"])
                m = U.powmod(c, d, n)
                if U.powmod(m, e, n) == c % n:
                    res = Result("boneh_durfee(sage)", m,
                                 f"Sage LLL 恢复 d（{d.bit_length()} bit）")
                    _SAGE_CACHE[key] = res
                    return res
        except Exception:
            continue
    _SAGE_CACHE[key] = None
    return None


# --------------------------------------------------------------------------
# 注册表：顺序即优先级
# --------------------------------------------------------------------------
Attack = Tuple[str, Callable[[RSAContext, object], Optional[Result]], str]

PIPELINE: List[Attack] = [
    ("mt_replay", attack_mt_replay, "MT19937 状态恢复 + 素数重放"),
    ("known_pq", attack_known_pq, "已知 p、q 直接解密"),
    ("known_d", attack_known_d, "已知私钥 d"),
    ("dp_dq_leak", attack_dp_leak, "dp/dq 泄露"),
    ("c_gcd_n", attack_c_share_factor, "gcd(c,n) 泄露因子"),
    ("d_leak", attack_d_factor, "已知 d 反推因子"),
    ("small_q", attack_small_q, "n 有小素因子"),
    ("common_factor", attack_common_factor, "多模数共享素因子"),
    ("fermat", attack_fermat, "p、q 接近（Fermat）"),
    ("wiener", attack_wiener, "小私钥 d（连分数）"),
    ("approx_power", attack_approx_power, "e ≈ n^k·v/u 型（幂和反推分解）"),
    ("common_modulus", attack_common_modulus, "共模攻击"),
    ("hastad", attack_hastad, "低指数广播"),
    ("small_e_root", attack_small_e_root, "低指数小明文直接开方"),
    ("sage_heavy", attack_sage_heavy, "Sage 重型（Coppersmith / Boneh-Durfee）"),
    ("franklin_reiter", attack_franklin_reiter, "相关消息攻击"),
    ("partial_p", attack_partial_p, "已知 p 高位/低位（纯 Python Coppersmith）"),
    ("m_high", attack_m_high, "已知明文高位（纯 Python Coppersmith）"),
    ("stereotyped", attack_stereotyped, "已知明文前后缀"),
    ("boneh_durfee", attack_boneh_durfee, "Boneh-Durfee（纯 Python 兜底）"),
    ("factordb", attack_factordb, "在线 FactorDB"),
    ("factorize", attack_generic_factor, "通用整数分解"),
]
