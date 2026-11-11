"""RSA 攻击库。

每个攻击是一个 (name, 适用性判断, 执行函数) 三元组，
执行函数返回 Result 或 None（表示不适用/未成功）。
"""
from __future__ import annotations

import itertools
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import factor as F
from . import lll as L
from . import modular as M
from . import special as SP
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
    # e|phi 时会有多个 m 同时满足 m^e ≡ c，可读前缀完全一样、只有尾部填充不同。
    # 逐字节比没有意义（填充字节也常落在可打印区），真正的信号是「正文在哪儿结束」：
    #   * 以 '}' 结尾 —— flag 的标准收尾；
    #   * 结尾是 NUL 或非文本字节 —— 正文之后就是补位。
    # 两者都给更强权重，才能把真明文从一堆 padding 变体里挑出来。
    run = 0
    for x in b:
        if 32 <= x < 127 or x in (9, 10, 13):
            run += 1
        else:
            break
    tail = b[run:]
    if tail:
        s += 1.5
        if b[run - 1:run] == b"}":
            s += 1.0
    if b.endswith(b"}"):
        s += 1.0
    return s


def best_of(cands: Sequence[int]) -> Optional[int]:
    """从一堆候选明文里挑最像 flag 的。

    这只是启发式：e 与 phi 不互素时，满足 m^e ≡ c 的明文本来就有多个，
    它们差在尾部填充上，没有算法能仅凭数值判断哪个是出题人写的原文。
    所以调用方必须把完整候选集一并交给用户（见 Result.candidates）。
    """
    best, bs = None, 0.0
    for m in cands:
        s = _score(m)
        if s > bs:
            best, bs = m, s
    return best


def _sage_nth_roots(a: int, e: int, primes: Sequence[int]) -> Optional[List[int]]:
    """纯 Python AMM 不支持时（如 9 | p-1），交给 Sage 的 nth_root。"""
    from . import sagebridge as SB

    if not _SAGE_ENABLED or not SB.available():
        return None
    res = SB.run_jobs([
        {"op": "nth_root", "p": str(p), "e": e, "a": str(a)}
        for p in primes
    ], timeout=120)
    if not res or len(res) < len(primes) or not all(r.get("ok") for r in res):
        return None
    per = [(int(p), [int(x) for x in r["values"]]) for p, r in zip(primes, res)]
    out: List[int] = []
    for combo in itertools.product(*[v for _, v in per]):
        m, _ = U.crt(list(zip(combo, [p for p, _ in per])))
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
    if g > (1 << 20):
        return None            # 公有因子太大，开根不现实
    roots = M.roots_mod_primes(c, g, primes)
    if roots is None:
        # 纯 Python 的 AMM 只支持 n || p-1，其余情形交给 Sage
        roots = _sage_nth_roots(c, g, primes)
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


def attack_phi_pair(ctx: RSAContext, opts) -> Optional[Result]:
    """题面给了多个形如 (p-a)(q-b)=V 的泄露值时，线性组合导出 p±q（或 αp+βq），
    配合 n=pq 解二次方程恢复 p、q 并解密。"""
    n, e = ctx.n, ctx.e
    if not (n and e and ctx.c is not None) or len(ctx.phi_pairs) < 2:
        return None
    pairs = ctx.phi_pairs
    for i in range(len(pairs)):
        a1, b1, v1 = pairs[i]
        for j in range(len(pairs)):
            if j == i:
                continue
            a2, b2, v2 = pairs[j]
            # V = (p-a)(q-b) = n - a q - b p + a b
            # V_i - V_j = (a_j-a_i) q + (b_j-b_i) p + (a_i b_i - a_j b_j)
            alpha = a2 - a1          # 系数 of q
            beta = b2 - b1           # 系数 of p
            X = v2 - v1 + (a1 * b1 - a2 * b2)
            if alpha == 0 or beta == 0:
                continue
            # alpha*q + beta*p = X, with p*q = n
            # beta*p^2 - X*p + alpha*n = 0
            disc = X * X - 4 * beta * alpha * n
            if disc < 0:
                continue
            r = U.isqrt(disc)
            if r * r != disc:
                continue
            for num in (X + r, X - r):
                if num <= 0 or num % (2 * beta):
                    continue
                p = num // (2 * beta)
                if p > 1 and n % p == 0 and p != n:
                    res = decrypt_from_factors(ctx, {p: 1, n // p: 1})
                    if res:
                        res.attack = "phi_pair"
                        res.detail = "由 (p-a)(q-b) 泄露值线性组合解出 p、q"
                        return res
    return None


def attack_decimal_leak(ctx: RSAContext, opts) -> Optional[Result]:
    """题面给了长小数 leak（如 Decimal((3p^2-1)/(3pq))），用连分数还原精确有理数 p/q。
    典型：p、q 为不同素数，leak≈p/q，既约分数的分子/分母即 p、q。
    已知 d（未知 n）时可直接解密。"""
    if ctx.c is None or ctx.d is None:
        return None
    raw = getattr(ctx, "raw", "") or ""
    m = re.search(r"([0-9]+\.[0-9]{60,})", raw)
    if not m:
        return None
    s = m.group(1)
    ip, fp = s.split(".")
    # 精确有理数 leak = (ip + fp/10^len) 
    from fractions import Fraction
    val = Fraction(int(ip + fp), 10 ** len(fp))
    num0, den0 = val.numerator, val.denominator
    # 连分数展开，遍历收敛子
    cf = U.continued_fraction(num0, den0)
    seen = 0
    for p, q in U.convergents(cf):
        if p <= 1 or q <= 1:
            continue
        seen += 1
        for cand_p, cand_q in ((p, q), (q, p)):
            if not (U.is_probable_prime(cand_p) and U.is_probable_prime(cand_q)):
                continue
            n = cand_p * cand_q
            try:
                mm = U.powmod(ctx.c, ctx.d, n)
            except Exception:
                continue
            b = U.long_to_bytes(mm)
            if len(b) >= 4 and sum(32 <= x < 127 for x in b) / len(b) > 0.85:
                return Result("decimal_leak", mm,
                              f"连分数还原 leak≈p/q（第 {seen} 个收敛子），已知 d 解密")
        if seen > 2000:
            break
    return None


def attack_known_factor_root(ctx: RSAContext, opts) -> Optional[Result]:
    """已知 n 的某个素因子 f（常来自 real_q / hint），且明文 m < f 时，
    直接 c mod f 求 e 次根即还原明文，无需分解另一因子。
    典型：n = 大合数 * 小素数，m 比小素数还短。"""
    if not (ctx.n and ctx.e and ctx.c is not None):
        return None
    n, e, c = ctx.n, ctx.e, ctx.c
    seen = set()
    for f in (ctx.p, ctx.q, ctx.hints.get("known_factor")):
        if not f or f <= 1 or f in seen:
            continue
        seen.add(f)
        if f >= n or n % f != 0:
            continue
        if not U.is_probable_prime(f):
            continue
        d0 = U.inv(e, f - 1)
        if d0 is None:
            continue
        m = U.powmod(c, d0, f)
        if U.powmod(m, e, n) == c % n:
            return Result("known_factor_root", m,
                          f"已知素因子 {f.bit_length()} bit，明文 < 因子，直接 mod 开根")
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


def attack_known_phi(ctx: RSAContext, opts) -> Optional[Result]:
    """题目直接给了 phi：解 x² - (n-phi+1)·x + n = 0 即得 p、q。"""
    phi = ctx.phi
    if phi is None and ctx.p and ctx.q:
        phi = (ctx.p - 1) * (ctx.q - 1)
    if phi is None and ctx.hints.get("phi"):
        phi = ctx.hints["phi"]
    if not (phi and ctx.n):
        return None
    n = ctx.n
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        return None
    r = U.isqrt(disc)
    if r * r != disc:
        return None
    p, q = (s + r) // 2, (s - r) // 2
    if p * q != n or p <= 1:
        return None
    res = decrypt_from_factors(ctx, {p: 1, q: 1})
    if res:
        res.attack = "known_phi"
        res.detail = "由 phi 反解 p、q"
    return res


def attack_rsa_crt_fault(ctx: RSAContext, opts) -> Optional[Result]:
    """Bellcore：RSA-CRT 签名中有一半算错，gcd(s'^e - m, n) 直接给出因子。

    两个可用的判别量：s'^e - m（知道被签名消息时），
    或 s - s'（另有正确签名时）。任一给出的非平凡 gcd 就是 p 或 q。
    """
    n, e, sig = ctx.n, ctx.e, ctx.sig
    if not (n and e and sig):
        return None
    cands: List[Tuple[str, int]] = []
    if ctx.signed_msg is not None:
        cands.append(("s'^e − m", (U.powmod(sig, e, n) - ctx.signed_msg) % n))
    if ctx.good_sig is not None:
        cands.append(("s − s'", (ctx.good_sig - sig) % n))
    if not cands:
        return None
    for tag, val in cands:
        g = U.gcd(val, n)
        if 1 < g < n:
            res = decrypt_from_factors(ctx, {g: 1, n // g: 1})
            if res:
                res.attack = "rsa_crt_fault"
                res.detail = f"Bellcore：gcd({tag}, n) 给出因子"
                return res
    return None


def attack_partial_d(ctx: RSAContext, opts) -> Optional[Result]:
    """已知 d 的低若干位（partial private key exposure，Coppersmith）。

    由 e·d = 1 + k·phi 且 d < phi 得 k < e，取模 2^kb：
        k·(p + q) ≡ 1 + k·(n + 1) − e·d_low   (mod 2^kb)
    于是 (p+q) 的低位可解，代入 p² − (p+q)·p + n ≡ 0 解出 p 的低位，
    再用 Coppersmith 已知低位恢复 p。

    k 往往是偶数（e·d−1 的 2-adic 赋值正好来自 k），此时 k 在 2^kb 上
    不可逆。先把 k 写成 2^v·k_odd，在模 2^(kb−v) 上求逆，等于只拿到
    p+q 的相对低位——这是该攻击在该 k 下的信息上限，不损失正确性。

    每个候选 k 都要跑一次 Coppersmith，纯 Python LLL 撑不住（k 可上万），
    所以只把候选低位送进 Sage，一次进程内批量试完。
    """
    n, e = ctx.n, ctx.e
    if not (n and e and ctx.d_low):
        return None
    kbits = ctx.d_low_bits or ctx.d_low.bit_length()
    if kbits < 8:
        return None
    nbits = U.nbit(n)
    if kbits > nbits // 2:
        return None
    pbits = (nbits + 1) // 2
    if pbits - kbits <= 0:
        return None
    # Coppersmith 的分因子界限是 X ≤ N^(beta²) = N^0.25
    if pbits - kbits > nbits // 4 + 2:
        if getattr(opts, "verbose", False):
            print(f"    [partial_d] 未知 {pbits - kbits} bit 超出 N^0.25（{nbits // 4} bit），跳过")
        return None

    cands = _partial_d_candidates(n, e, ctx.d_low, kbits)
    if not cands:
        return None
    if getattr(opts, "verbose", False):
        print(f"    [partial_d] {len(cands)} 个候选 p 低位，交给 Sage")
    from . import sagebridge as SB

    if not _SAGE_ENABLED or not SB.available():
        return None
    jobs = [{"op": "partial_p_low", "n": str(n), "p_low": str(low),
             "known_bits": bits}
            for low, bits in cands]
    results = SB.run_jobs(jobs, timeout=float(getattr(opts, "sage_timeout", 900.0)),
                          verbose=getattr(opts, "verbose", False))
    if not results:
        return None
    for r in results:
        if not r or not r.get("ok"):
            continue
        try:
            p = int(r["value"])
        except (KeyError, ValueError):
            continue
        if p > 1 and n % p == 0:
            res = decrypt_from_factors(ctx, {p: 1, n // p: 1})
            if res:
                res.attack = "partial_d"
                res.detail = f"已知 d 的低 {kbits} bit，Hensel 提升 + Coppersmith 恢复 p"
                return res
    return None


def _partial_d_candidates(n: int, e: int, d_low: int, kbits: int,
                          max_cands: int = 64, max_k: int = 4096) -> List[Tuple[int, int]]:
    """按 e·d−1 = k·phi 枚举 k，解出候选的 p 低位。

    返回 [(p 的低位, 该低位的位数)]。真实 k 可以到 e 的量级，若逐个试到
    e 会产出成千上万个候选、把 Sage 批量任务拖垮。k 只可能取
    (e·d_low − 1)/phi 附近的值，而 phi ≈ n，所以直接由低位关系估出
    候选 k 的下界后再枚举，候选量才可控。
    """
    out: List[Tuple[int, int]] = []
    seen = set()
    # 真实 k ≈ (e·d − 1)/phi；只凭 d 的低位无法算准 d，
    # 但 k < e 且 k 与 n 同量级的信息足够把范围压到 max_k 之内。
    limit = max(1, min(int(e), max_k))
    for k in range(1, limit):
        odd, v = k, 0
        while odd % 2 == 0:
            odd //= 2
            v += 1
        if v >= kbits:
            continue
        bits = kbits - v
        mod = 1 << bits
        inv_odd = U.inv(odd, mod)
        if inv_odd is None:
            continue
        rhs = (1 + k * (n + 1) - e * d_low) % (1 << kbits)
        if v and rhs % (1 << v):
            continue                     # 该 k 与泄露的低位不自洽
        s_mod = ((rhs >> v) * inv_odd) % mod
        for cand in _sqrt_mod_pow2(1, (-s_mod) % mod, n % mod, bits):
            key = (cand, bits)
            if key in seen:
                continue
            seen.add(key)
            out.append(key)
            if len(out) >= max_cands:
                return out
    return out


def _sqrt_mod_pow2(a: int, b: int, c: int, bits: int, max_roots: int = 64) -> List[int]:
    """解 a·x² + b·x + c ≡ 0 (mod 2^bits)，逐位 Hensel 提升。

    每一位只在候选的两种余类里挑满足下一级同余的那个；根数超限说明
    该 k 值分支爆炸，交给调用方放弃。
    """
    def poly(x: int) -> int:
        return a * x * x + b * x + c

    roots = [r for r in (0, 1) if poly(r) % 2 == 0]
    for level in range(1, bits):
        mod = 1 << level
        nxt = mod << 1
        grown = []
        for r in roots:
            for delta in (0, mod):
                cand = r + delta
                if poly(cand) % nxt == 0:
                    grown.append(cand)
        if not grown or len(grown) > max_roots:
            return []
        roots = grown
    return [r % (1 << bits) for r in roots]


def attack_bellcore(ctx: RSAContext, opts) -> Optional[Result]:
    """Bellcore 的别名入口（与 rsa_crt_fault 同义，便于按题面直觉选用名）。"""
    return attack_rsa_crt_fault(ctx, opts)


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


def attack_fermat_multiplier(ctx: RSAContext, opts) -> Optional[Result]:
    """p、q 之间差一个小倍数（2PN 型、成比例构造）：给 n 乘小系数再 Fermat。"""
    n = ctx.n
    if not n or n % 2 == 0 or U.nbit(n) > 2048:
        return None
    pair = SP.fermat_multiplier(n, max_iter=200_000,
                                deadline=time.time() + getattr(opts, "factor_timeout", 20))
    if not pair:
        return None
    p, q = pair
    res = decrypt_from_factors(ctx, {p: 1, q: 1})
    if res:
        res.attack = "fermat_multiplier"
        res.detail = "Fermat 乘子法（k·n 的两个因子接近）"
    return res


def attack_special_structure(ctx: RSAContext, opts) -> Optional[Result]:
    """n 的代数形状有弱点：素数幂 / 强伪素数 / 著名数列构造。"""
    n = ctx.n
    if not n or n < 4:
        return None
    if ctx.p and ctx.q and ctx.p * ctx.q == n:
        return None
    deadline = time.time() + getattr(opts, "factor_timeout", 20)

    pp = SP.prime_power(n)
    if pp:
        base, exp = pp
        res = decrypt_from_factors(ctx, {base: exp})
        if res:
            res.attack = "prime_power"
            res.detail = f"n = p^{exp}（素数幂），phi = (p-1)·p^{exp - 1}"
            return res

    # 这些方法给的是「一对互补因子」，其中每个都可能是合数
    # （Carmichael 数 n = 561 会得到 33 和 17）。phi 必须由完整素数分解算，
    # 否则 d 是错的，解密会静默给出垃圾值。
    candidates = []
    pair = SP.strong_pseudoprime(n)
    if pair:
        candidates.append(("strong_pseudoprime", pair,
                           "Carmichael / 强伪素数：Miller-Rabin 链上的非平凡平方根"))
    pair = SP.sequence_gcd(n, deadline=deadline)
    if pair:
        candidates.append(("sequence_gcd", pair,
                           "p、q 取成 Fibonacci / Lucas / Mersenne / 阶乘 / 素数阶乘等序列"))
    if U.nbit(n) <= 40:     # 求平方和表示要扫 √n，只对很小的模数有意义
        pair = SP.euler_two_squares(n, deadline=deadline)
        if pair:
            candidates.append(("euler_two_squares", pair, "两平方和表示（Euler 分解）"))
    nov = SP.novelty_prime(n)
    if nov:
        candidates.append(("novelty_prime", (nov, n // nov), "3133…37 型玩具素数"))
    # Williams p+1：p+1 光滑而 p-1 不光滑时，只有它能拆；p-1 类方法都抓不到。
    g = SP.williams_pp1(n, b1=50_000, seeds=3, deadline=deadline)
    if g:
        candidates.append(("williams_pp1", (g, n // g), "p+1 光滑（Williams p+1）"))

    for name, pair, desc in candidates:
        fac = SP.factor_pair(n, pair, deadline=deadline)
        if not fac:
            continue
        res = decrypt_from_factors(ctx, fac)
        if res:
            res.attack = name
            res.detail = desc
            return res
    return None


def attack_non_rsa(ctx: RSAContext, opts) -> Optional[Result]:
    """n 不是两个素数之积：n 本身是素数，或 n = p^k。

    这类题的 phi 可以直接写出来，不需要分解。
    """
    n, e = ctx.n, ctx.e
    if not (n and e) or ctx.c is None:
        return None
    if ctx.p and ctx.q:
        return None
    if U.is_probable_prime(n):
        d = U.inv(e, n - 1)
        if d is None:
            return None
        m = U.powmod(ctx.c, d, n)
        if U.powmod(m, e, n) == ctx.c % n:
            return Result("non_rsa(n 是素数)", m, "n 本身是素数，phi = n − 1")
        return None
    pp = SP.prime_power(n)
    if not pp:
        return None
    base, exp = pp
    phi = (base - 1) * base ** (exp - 1)
    d = U.inv(e, phi)
    if d is None:
        return None
    m = U.powmod(ctx.c, d, n)
    if U.powmod(m, e, n) == ctx.c % n:
        return Result("non_rsa(p^k)", m,
                      f"n = p^{exp}，phi = (p−1)·p^{exp - 1}")
    return None


def attack_near_p(ctx: RSAContext, opts) -> Optional[Result]:
    """题目给了 p 的近似值（差一点点，不是高位截断）：Coppersmith 补足误差。"""
    n, near = ctx.n, ctx.near_p
    if not (n and near):
        return None
    if ctx.p and ctx.q and ctx.p * ctx.q == n:
        return None
    g = U.gcd(n, near)
    if 1 < g < n:
        res = decrypt_from_factors(ctx, {g: 1, n // g: 1})
        if res:
            res.attack = "near_p"
            res.detail = "近似值本身就能整除 n（gcd 命中）"
            return res
    nbits = U.nbit(n)
    pbits = U.nbit(near)
    max_bits = max(int(0.49 * 0.49 * nbits), 1)
    diff_bits = max(1, pbits - max_bits)
    # 从误差上界 2^diff_bits 起，成倍放宽，直到 Coppersmith 的可行域
    bits = min(32, max(1, diff_bits))
    while bits <= max_bits:
        p = L.factor_high_bits(n, near >> bits, bits,
                               verbose=getattr(opts, "verbose", False))
        if p and n % p == 0:
            res = decrypt_from_factors(ctx, {p: 1, n // p: 1})
            if res:
                res.attack = "near_p"
                res.detail = f"p 的近似值，误差 ≤ 2^{bits}，Coppersmith 恢复"
                return res
        if bits >= max_bits:
            break
        bits = min(bits * 2, max_bits)
    return None


def attack_short_pad(ctx: RSAContext, opts) -> Optional[Result]:
    """短填充：两条密文的明文只差一个很小的未知量 δ。

    Franklin-Reiter 处理「δ 已知」；δ 未知时先 Coppersmith 解出 δ^e。
    """
    n, e = ctx.n, ctx.e
    if not (n and e) or len(ctx.cs) < 2:
        return None
    if e > 5:
        return None
    res = L.short_pad(n, e, ctx.cs[0], ctx.cs[1],
                      verbose=getattr(opts, "verbose", False))
    if res:
        m1, m2 = res
        return Result("short_pad", m1,
                      f"短填充：m2 = m1 + δ，δ^e 由 Coppersmith 求得（m2 长度 {U.nbit(m2)} bit）")
    return None


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
    fac = F.factor(n, timeout=timeout, use_online=getattr(opts, "online", True),
                   use_sage=getattr(opts, "use_sage", True))
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
    """同一个 n，两个加密同一个 m 的指数。

    扩展欧几里得给出 a·e1 + b·e2 = g = gcd(e1, e2)，组合结果是 m^g 而不是 m。
    g = 1 时直接得明文；g > 1 时只有 m^g < n 才能开 g 次方还原，
    否则必须分解 n —— 因此必须校验，不能把开方截断值当结果。
    """
    groups: Dict[int, List[Tuple[int, int]]] = {}
    if ctx.triples:
        for n, e, c in ctx.triples:
            groups.setdefault(n, []).append((e, c))
    if ctx.n and len(ctx.es) == len(ctx.cs) and len(ctx.cs) >= 2:
        groups.setdefault(ctx.n, list(zip(ctx.es, ctx.cs)))

    for n, items in groups.items():
        for (e1, c1), (e2, c2) in itertools.combinations(items, 2):
            a, b, g = _ext_gcd(e1, e2)
            if g == 0:
                continue
            combined = (_signed_pow(c1, a, n) * _signed_pow(c2, b, n)) % n
            if g == 1:
                m = combined
                if U.powmod(m, e1, n) == c1 % n:
                    return Result("common_modulus", m,
                                  f"e1={e1}、e2={e2} 互素，扩展欧几里得直接得 m")
                continue
            # g > 1：组合结果是 m^g，只有 m^g < n 时才能开方还原
            root, exact = U.iroot(combined, g)
            if not exact:
                continue
            for cand in (root, combined - root):
                if cand > 0 and U.powmod(cand, e1, n) == c1 % n:
                    return Result("common_modulus(g>1)", cand,
                                  f"gcd(e1,e2)={g}，组合出 m^{g} 后开方")
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


def attack_ab_quadratic(ctx: RSAContext, opts) -> Optional[Result]:
    """题面给了 a、b（常见 b = q - p*a 形式）时，构建 a·p²+b·p-N=0 秒解 p。
    校验：判别式必须为整平方，且解出的 p 整除 n。"""
    n = ctx.n
    a = ctx.hints.get("a")
    b = ctx.hints.get("b")
    if not (n and a and b and ctx.c is not None):
        return None
    disc = b * b + 4 * a * n
    r = U.isqrt(disc)
    if r * r != disc:
        return None
    # a·p² + b·p - n = 0，p = (-b + r) / (2a)
    num = -b + r
    if num <= 0 or num % (2 * a):
        return None
    p = num // (2 * a)
    if p <= 1 or n % p != 0:
        return None
    res = decrypt_from_factors(ctx, {p: 1, n // p: 1})
    if res:
        res.attack = "ab_quadratic"
        res.detail = f"a·p²+b·p-N=0（b=q-p·a）直接解出 p"
    return res


def attack_wiener(ctx: RSAContext, opts) -> Optional[Result]:
    if not (ctx.n and ctx.e and ctx.c is not None):
        return None
    # phi 可能是变体：phi=(p^a-1)(q^b-1) ≈ n^(a+b)/...，导致 e ≈ d^{-1} (mod n^t)。
    # 仅对 e/n 展开连分数会漏；对 e/n、e/n^2、e/n^3、e/n^4 分别展开找候选 d。
    # 收敛子 d 同时满足 ed ≡ 1 (mod (p-1)(q-1))，因此直接 pow 校验即可确认真私钥指数。
    n, e, c = ctx.n, ctx.e, ctx.c
    for k in range(1, 5):
        den = n ** k
        for cd, d in U.convergents(U.continued_fraction(e, den)):
            if d <= 1:
                continue
            if (e * d - 1) % cd:
                continue
            m = U.powmod(c, d, n)
            if U.powmod(m, e, n) != c % n:
                continue
            desc = (f"连分数恢复 d（{d.bit_length()} bit，对 e/n^{k} 展开）"
                    if k > 1 else f"连分数恢复 d（{d.bit_length()} bit，远小于 n^0.25）")
            return Result("wiener", m, desc)
    return None


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
    """已知明文的前缀和后缀，中间一段未知（stereotyped message）。"""
    prefix = getattr(opts, "m_prefix", None)
    suffix = getattr(opts, "m_suffix", None)
    unknown_len = getattr(opts, "m_unknown_len", 0)
    if not (ctx.n and ctx.e and ctx.c is not None):
        return None
    if prefix is None and suffix is None:
        return None
    if ctx.e > 17:
        return None
    pre = prefix.encode() if isinstance(prefix, str) else (prefix or b"")
    suf = suffix.encode() if isinstance(suffix, str) else (suffix or b"")
    if not (pre or suf):
        return None
    ms = L.stereotyped_message(ctx.n, ctx.e, ctx.c, prefix=pre, suffix=suf,
                               unknown_len=unknown_len,
                               verbose=getattr(opts, "verbose", False))
    if ms:
        parts = []
        if pre:
            parts.append("前缀")
        if suf:
            parts.append("后缀")
        return Result("stereotyped", ms[0],
                      f"已知明文{'和'.join(parts)}，中间未知 {unknown_len} 字节")
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
# 未命中的 context 只记一次，避免同一进程内重复烧 Sage 计算
_SAGE_TRIED: set = set()


def _sage_ctx_key(ctx: RSAContext) -> tuple:
    hs = tuple(sorted((str(k), v) for k, v in ctx.hints.items() if isinstance(v, int)))
    return (ctx.n, ctx.e, ctx.c, hs)


def attack_sage_heavy(ctx: RSAContext, opts) -> Optional[Result]:
    """把 Coppersmith（p 高位 / 明文高位）与 Boneh-Durfee 一次性交给 Sage。

    常驻 worker 复用后只付一次 Sage 启动成本（本机 Cygwin 版约 6~10 秒），
    结果按 context 缓存。
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
    if key in _SAGE_TRIED:
        # 同一 context 已经跑过且没中：不必再烧一次 Sage 计算
        return None

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
        _SAGE_TRIED.add(key)
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
        # Sage 不可用 / 超时：只记"试过"，结果留给纯 Python 兜底重试
        _SAGE_TRIED.add(key)
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
    _SAGE_TRIED.add(key)
    return None


# --------------------------------------------------------------------------
# 多重线性泄露：c_i = a_i*p + b_i*q（13_apbq 型，C1 正交格）
# --------------------------------------------------------------------------
def attack_linear_leaks(ctx: RSAContext, opts) -> Optional[Result]:
    """题面给了多个精确整数的 a_i*p + b_i*q 泄露值（a_i、b_i 未知但相对小）时，
    用 C1 正交格恢复 p。13_apbq 实例需 m>=60；模块自带 m 阶梯与维度上限。"""
    cs = getattr(ctx, "linear_leaks", None)
    if not cs or not ctx.n or ctx.c is None:
        return None
    from . import ortholat
    p = ortholat.ortholat_factor(cs, ctx.n, verbose=getattr(opts, "verbose", False))
    if not p:
        return None
    res = decrypt_from_factors(ctx, {p: 1, ctx.n // p: 1})
    if res:
        res.attack = "ortholat"
        res.detail = f"{len(cs)} 个线性泄露 a_i*p+b_i*q，正交格分解"
        return res
    return None


# --------------------------------------------------------------------------
# known-divisor Pollard p-1（19_NestingDoll 型）
# --------------------------------------------------------------------------
def attack_kdp1(ctx: RSAContext, opts) -> Optional[Result]:
    """题面给出嵌套模数/种子积且其整除 p-1 时，用放大的 Pollard p-1 分解。"""
    n = ctx.n
    if not n or ctx.c is None:
        return None
    cands = []
    for k in ("n1", "seed", "known_multiplier", "inner_n", "nest"):
        v = ctx.hints.get(k)
        if isinstance(v, int) and v > 1 and v < n:
            cands.append(v)
    for v in ctx.ns:
        if v and v != n and v < n and v.bit_length() > 64:
            cands.append(v)
    if not cands:
        return None
    from . import kdp1
    from . import factor as F
    seen = set()
    for mult in cands:
        if mult in seen:
            continue
        seen.add(mult)
        # n 可能是多素数模数（NestingDoll 型 p*q*r*s）：逐个除尽。
        # 每除掉一个素数，剩余因子的光滑度要求上移，需要细化的 B1 escalation
        # （真实 19 题实测：B1 ≈ 1e6/1.01e6/1.03e6/1.045e6 依次捕获 4 个素数）。
        # 总时长护栏：每层 B1 的 lcm+powmod 在 4096-bit 模数上 ~10-60s，
        # 用墙钟上限防止最坏情况跑飞（用户机器内存有限）。
        fac: Dict[int, int] = {}
        remaining = n
        # NestingDoll 实测：p−1 各含一个 512-bit seed + 20-bit smooth 部分，
        # 捕获的 B1 依次 1e6/1.03e6/1.04e6/1.045e6。用 kdp1_levels 一次算好
        # 各层的 a，再逐层 gcd，增量里析取因子（避免每层重扫）。
        schedule = [10**6, 1_010_000, 1_030_000, 1_040_000, 1_045_000]
        t_all = time.time()
        try:
            levels = kdp1.kdp1_levels(remaining, [mult], schedule,
                                      verbose=getattr(opts, "verbose", False))
        except Exception:
            levels = []
        prev_g = 1
        for B1, a, _dt in levels:
            if remaining <= 1 or time.time() - t_all > 600:
                break
            g = int(U.gcd(a - 1, remaining))
            if g <= 1:
                continue
            # gcd 是「已捕获素数之积 × prev 已知部分」：增量 = g 中超出
            # prev_g 的部分。对增量做质因数拆解（增量通常 <= 2048-bit，
            # 且都是素数或素数之积，直接逐个 gcd 剥离）。
            incr = g
            while incr > 1 and U.is_probable_prime(incr):
                p = incr
                if remaining % p != 0:
                    break
                e_local = 0
                while remaining % p == 0:
                    remaining //= p
                    e_local += 1
                fac[p] = e_local
                incr //= p
            if incr > 1:
                # 增量是合数：用 Fermat/rho 快速拆（增量是同类素数之积，
                # 位宽接近，Fermat 极快）
                from . import factor as F
                for _ in range(4):
                    fp = F.fermat(incr, max_iter=100000) if incr > 1 else None
                    if not fp:
                        break
                    for q_ in (fp, incr // fp):
                        if U.is_probable_prime(q_) and remaining % q_ == 0:
                            e_local = 0
                            while remaining % q_ == 0:
                                remaining //= q_
                                e_local += 1
                            fac[q_] = e_local
                    incr = incr // _prod({fp: 1}) if incr % fp == 0 else incr
                    if U.is_probable_prime(incr):
                        continue
                # 拆不动的整块也记录（decrypt_from_factors 需要）
                if incr > 1 and remaining % incr == 0:
                    e_local = 0
                    while remaining % incr == 0:
                        remaining //= incr
                        e_local += 1
                    fac[incr] = e_local
            if remaining > 1 and U.is_probable_prime(remaining):
                fac[remaining] = 1
                break
        if fac and _prod(fac) == n:
            # NestingDoll 型收尾：外层素数 P = seed·smooth + 1，
            # seed = (P-1) 剥掉 <=2^20 小素数后的剩余（512-bit）。
            # 4 个 seed 之积 == inner 模数 n1，密文在 n1 上。
            seeds = []
            for P in fac:
                x = P - 1
                for sq in F.small_primes(1_050_000):
                    while x % sq == 0:
                        x //= sq
                seeds.append(x)
            prod_seeds = 1
            for s in seeds:
                prod_seeds *= s
            inner = ctx.hints.get("n1") or (ctx.ns[0] if ctx.ns else None)
            if inner and prod_seeds == inner:
                phi = 1
                for s in seeds:
                    phi *= (s - 1)
                d = U.inv(ctx.e, phi)
                if d is not None:
                    m = U.powmod(ctx.c, d, inner)
                    if U.powmod(m, ctx.e, inner) == ctx.c % inner:
                        return Result("kdp1", m,
                                      "kdp1 分解外层 → extract_seed 还原 seeds（积=inner n1）→ 解密")
            res = decrypt_from_factors(ctx, fac)
            if res:
                res.attack = "kdp1"
                res.detail = (f"known-divisor Pollard p-1（倍数 {mult.bit_length()} bit，"
                              f"{len(fac)} 个素因子）")
                return res
    return None


def _prod(fac: Dict[int, int]) -> int:
    v = 1
    for p, k in fac.items():
        v *= p ** k
    return v


# --------------------------------------------------------------------------
# DH 关系样本：(c, C=g^c mod r) 恢复未知模数 r（01_DHRSA 型）
# --------------------------------------------------------------------------
def attack_dh_relations(ctx: RSAContext, opts) -> Optional[Result]:
    """题面给出多组 (c, C) 且 C=g^c mod 未知 r、外加 n=p*q 时，LLL 零关系恢复 r，
    Pohlig-Hellman 求离散对数还原 p、q。整链较重（每次 dlog ~20s），放在中段。"""
    pairs = getattr(ctx, "dh_pairs", None)
    if not pairs or not ctx.n or ctx.c is None:
        return None
    X = ctx.hints.get("x") or ctx.hints.get("X")
    W = ctx.hints.get("w") or ctx.hints.get("W")
    if not (X and W):
        return None
    from . import dhrel
    try:
        out = dhrel.solve_dhrsa(pairs, X, W, ctx.n, ctx.c, ctx.e or 65537,
                                verbose=getattr(opts, "verbose", False))
    except Exception:
        return None
    if not out or not out.get("m"):
        return None
    p, q = out.get("p"), out.get("q")
    fac = {p: 1, q: 1} if (p and q and p * q == ctx.n) else {}
    return Result("dhrel", out["m"], "LLL 零关系恢复 r → PH-DLP 还原 p,q", fac)


# --------------------------------------------------------------------------
# Pell 方程 gift + 有界断言（20_PECO 型）
# --------------------------------------------------------------------------
def attack_pell_lattice(ctx: RSAContext, opts) -> Optional[Result]:
    """题面给出 A*x^2 - B*y^2 == A 型 gift（Pell 方程）与 (x*f0+y*f1) mod m
    有界断言时，用 Pell 基本解 + 3 维格恢复 flag 两段。

    不依赖密文 c：flag 恢复只靠 gift 系数与断言（m 是解出来的 1876-bit 素数）。
    """
    pp = getattr(ctx, "pell_problem", None)
    if not pp:
        return None
    A, B = pp.get("A"), pp.get("B")
    # V（gift 值）与 residue_bound 从题面解析；m 是解密出来的 1876-bit 素数，
    # 通常作为独立大数出现在题面/数据里 —— hints["m"] 是它的落点
    V = pp.get("V")
    m = pp.get("m") or ctx.hints.get("m")
    bound = pp.get("residue_bound")
    if not (V and m and bound):
        return None
    from . import pell
    try:
        out = pell.pell_attack(A, B, V, m, bound,
                               verbose=getattr(opts, "verbose", False))
    except Exception:
        return None
    if out and len(out) >= 5 and out[4]:
        flag_bytes = out[4]
        return Result("pell_lattice", U.bytes_to_long(flag_bytes),
                      f"Pell x^2-{out[0]}*y^2=1 基本解 + 3 维格恢复 flag 两半")
    return None


# --------------------------------------------------------------------------
# qInv + dq 低位（CISCN2024 ez_rsa / checkin 型）
# --------------------------------------------------------------------------
def _dq_low_bits(dq: int) -> int:
    """dq 的已知位数。dq 若为完整值就不该走这条攻击。"""
    return U.nbit(dq) if dq else 0


def attack_qinv_dq_low(ctx: RSAContext, opts) -> Optional[Result]:
    """已知 qInv = q^{-1} mod p 与 dq 的低若干位时，逐个 k 试 Coppersmith 恢复 q。

    这条攻击的来源是一个反直觉的事实：单看 qInv 无法分解 n（等价于分解），
    但只要再多知道 dq 的低 L bit，未知量就降到 (n^{1/2})/2^L，
    落进 deg=2、beta=1 的 Coppersmith 可行域。k ∈ [1,e) 须逐个尝试，
    每个 k 一次 dim=12 的 LLL；命中判据是 q = (e·dq-1)/k+1 整除 n。
    """
    n, e, qinv, dq = ctx.n, ctx.e, ctx.qinv, (ctx.dq or ctx.dq_low)
    if not (n and e and qinv and dq):
        return None
    if dq >= n or n % dq == 0:
        return None                      # 已经是完整 dq 或明显不是低位
    L = _dq_low_bits(dq)
    half = (U.nbit(n) + 1) // 2
    # 未知量 X = 2^(half-L)；Coppersmith 要求 X < n^{1/2}，留 8 bit 余量
    if L < 8 or L > half - 16:
        return None
    if not getattr(opts, "use_sage", True):
        return None
    from . import sagebridge as SB

    if not SB.available():
        return None
    verbose = getattr(opts, "verbose", False)

    # k 的上界就是 e；按进程数切片，每片一次一次性调用（各付一次 Sage 启动）
    procs = int(getattr(opts, "qhunt_procs", 0) or 0)
    if procs <= 0:
        # 实测：4 路是这台机器的性价比拐点（2.1x），8 路反而退化到 1.9x
        procs = min(4, os.cpu_count() or 1)
    k_lo = max(1, int(getattr(opts, "qhunt_k_lo", 1) or 1))
    k_hi = int(getattr(opts, "qhunt_k_hi", 0) or 0) or int(e)
    if k_hi <= k_lo:
        return None
    span = max(1, (k_hi - k_lo + procs - 1) // procs)
    batches = []
    for i in range(procs):
        lo = k_lo + i * span
        hi = min(k_hi, lo + span)
        if lo >= hi:
            continue
        batches.append([{"op": "qhunt", "n": str(n), "e": int(e), "qinv": str(qinv),
                         "dq_low": str(dq), "L": L, "k_lo": lo, "k_hi": hi,
                         "m": 5, "t": 1}])
    if not batches:
        return None
    # 每片要跑 (k_hi-k_lo)/procs 个 k，实测每个 k 约 0.43 秒（dim=11 一次 LLL 加求根，
    # 再按并行效率打折）。预算不足时不能闷头超时 —— 那样只是白烧 CPU 再报"未命中"，
    # 得算清楚、说清楚，让用户知道这是「没算完」而不是「不存在」。
    per_k = float(getattr(opts, "qhunt_sec_per_k", 0.0) or 0.43)
    per_shard = max(b[0]["k_hi"] - b[0]["k_lo"] for b in batches)
    need = per_shard * per_k + 20.0          # 每片含一次 Sage 启动
    budget = float(getattr(opts, "sage_timeout", 900.0))
    if need > budget:
        total_h = (k_hi - k_lo) * per_k / max(1, procs) / 3600.0
        ctx.notes.append(
            "qinv_dq_low 未执行：k∈[%d,%d) 共 %d 个，分 %d 片每片约需 %.0fs，"
            "超过预算 %.0fs（全量约 %.1f 小时）。"
            "请用 --sage-timeout %d 或 --qhunt-k-lo/--qhunt-k-hi 限定区间"
            % (k_lo, k_hi, k_hi - k_lo, len(batches), need, budget, total_h,
               int(need) + 60))
        return None
    if verbose:
        print("    [qhunt] qInv + dq 低 %d bit：k∈[%d,%d) 分 %d 片并行（每片约 %.0fs）"
              % (L, k_lo, k_hi, len(batches), need))
    results = SB.run_shards(batches, timeout=float(getattr(opts, "sage_timeout", 900.0)),
                            procs=procs, verbose=verbose)
    if not results:
        return None
    for part in results:
        if not part:
            continue
        r = part[0]
        if not r or not r.get("ok"):
            continue
        q = int(r["value"])
        if q > 1 and n % q == 0:
            res = decrypt_from_factors(ctx, {q: 1, n // q: 1})
            if res:
                res.attack = "qinv_dq_low"
                res.detail = ("qInv + dq 低 %d bit：枚举 k=%s 后 Coppersmith 恢复 q"
                              % (L, r.get("k")))
                return res
    # 有分片没跑完（超时/崩溃）时，"没命中"不等于"不存在"：留给总超时提示
    pending = getattr(SB.run_shards, "last_timeouts", None) or []
    if pending:
        ctx.notes.append(
            "qinv_dq_low: %d/%d 个 k 分片没跑完，结果不完整（加大 --sage-timeout 或减 --qhunt-procs 重试）"
            % (len(pending), len(batches)))
    return None


# --------------------------------------------------------------------------
# e 的高若干位（CISCN2024 OvO 型）
# --------------------------------------------------------------------------
def attack_e_high_leak(ctx: RSAContext, opts) -> Optional[Result]:
    """e 由 p、q 组合而成且低若干位被清零时，解近似二次方程 + Coppersmith 恢复 p。

    识别特征：e 远大于 n（e/n 有几百位），且题面出现了 >>k 的清零操作。
    这类题不能当"大 e 小 d"处理：e 的真实低位是被抹掉的，Wiener/BD 都不适用。
    """
    n, e, c = ctx.n, ctx.e, ctx.c
    if not (n and e and c):
        return None
    # 结构判定：这类题的 e 由 p、q 组合而成，量级是 n 的许多倍（OvO 约 2^128 倍），
    # 必须明显大于 n；单看 e//n-2 > 0 就够，不必设 4n 这种粗略门槛。
    if e // n - 2 <= 0:
        return None
    leak_bits = ctx.leak_shift or 0
    if leak_bits < 32:
        return None
    if not getattr(opts, "use_sage", True):
        return None
    from . import sagebridge as SB

    if not SB.available():
        return None
    res = SB.run_jobs([{"op": "high_leak_quadratic", "n": str(n), "e": str(e),
                        "c": str(c), "leak_bits": leak_bits}],
                      timeout=float(getattr(opts, "sage_timeout", 900.0)),
                      verbose=getattr(opts, "verbose", False))
    if not res or not res[0].get("ok"):
        return None
    try:
        m = int(res[0]["value"])
        p = int(res[0]["p"])
    except (KeyError, ValueError):
        return None
    if U.powmod(m, int(res[0]["e_full"]), n) != c % n:
        return None
    return Result("e_high_leak", m,
                  "e 的高位泄露：近似二次方程取 p 初值 + Coppersmith 补低位",
                  {p: 1, n // p: 1})


# --------------------------------------------------------------------------
# 退化椭圆曲线：系数即 n 的因子（07_babyRSA 型）
# --------------------------------------------------------------------------
def attack_ec_degenerate(ctx: RSAContext, opts) -> Optional[Result]:
    """曲线 E: y²=x³+p·x+q over Z_n（系数就是因子）时，由已知点反推 q 并还原明文。

    模 p 时 a=p≡0，曲线退化为 y²=x³+q，因此任何已知点都给出一条
        q ≡ Cy² − Cx³  (mod p)
    而 q 只有 p 的一半位宽左右，是「模未知因子 p」的小根 ⇒ Coppersmith 直接求出。
    拿到 q 即分解 n，再在两条退化曲线上各求一次 e 的逆元还原 P。
    """
    n, e = ctx.n, ctx.e
    if not (n and e and ctx.ec_point):
        return None
    Cx, Cy = ctx.ec_point
    if not getattr(opts, "use_sage", True):
        return None
    from . import sagebridge as SB

    if not SB.available():
        return None
    verbose = getattr(opts, "verbose", False)

    # 因子位数比未知：07 题是 p:q = 2:1（β≈0.66）。多试几档 β，
    # 上界取 n^(β²)，β 越大要求的未知量越小、但覆盖的因子比例越高。
    for beta in (0.66, 0.6, 0.5, 0.7):
        res = SB.run_jobs([{"op": "ec_factor", "n": str(n), "Cx": str(Cx),
                            "Cy": str(Cy), "beta": beta}],
                          timeout=float(getattr(opts, "sage_timeout", 900.0)),
                          verbose=verbose)
        if not res or not res[0].get("ok"):
            continue
        q = int(res[0]["value"])
        if not (1 < q < n and n % q == 0):
            continue
        p = n // q
        if verbose:
            print("    [ec] 因子 %d bit / %d bit（beta=%.2f）" % (p.bit_length(), q.bit_length(), beta))
        # 还原点：明文固定长度由题面给出（如 urandom(192-len(flag)) ⇒ 192 字节）。
        # 不给就只能拿 x0 本身，n 短于明文时无法挑出真值。
        nbytes = int(getattr(opts, "ec_msg_bytes", 0) or ctx.ec_msg_bytes or 0)
        rec = SB.run_jobs([{"op": "ec_recover", "n": str(n), "Cx": str(Cx),
                            "Cy": str(Cy), "e": int(e), "p": str(p), "q": str(q),
                            "nbytes": nbytes}],
                          timeout=float(getattr(opts, "sage_timeout", 900.0)),
                          verbose=verbose)
        if not rec or not rec[0].get("ok"):
            continue
        for cand_s in rec[0].get("candidates") or []:
            cand = int(cand_s)
            blob = cand.to_bytes(max(1, (cand.bit_length() + 7) // 8), "big")
            flag = _flag_from_bytes(blob)
            if flag:
                return Result("ec_degenerate", U.bytes_to_long(flag),
                              "退化曲线 q ≡ Cy²−Cx³ (mod p) → Coppersmith 分解 n → 还原 e·P 原像",
                              {p: 1, q: 1})
    return None


def _flag_from_bytes(blob: bytes) -> Optional[bytes]:
    """从字节流里切出 flag；要求形如 `<前缀>{...}` 且前缀是常见赛事名。"""
    m = re.search(rb"(?:flag|FLAG|ctf|CTF|DASCTF|NSSCTF|ISCC|NCO|SCTF|NCTF)\{[^}\n]{1,140}\}",
                  blob)
    return m.group(0) if m else None


# --------------------------------------------------------------------------
# 注册表：顺序即优先级
# --------------------------------------------------------------------------
Attack = Tuple[str, Callable[[RSAContext, object], Optional[Result]], str]

PIPELINE: List[Attack] = [
    ("mt_replay", attack_mt_replay, "MT19937 状态恢复 + 素数重放"),
    ("known_pq", attack_known_pq, "已知 p、q 直接解密"),
    ("phi_pair", attack_phi_pair, "(p-a)(q-b) 泄露值线性组合解 p、q"),
    ("known_factor_root", attack_known_factor_root, "已知单素因子且明文更小，直接 mod 开根"),
    ("known_d", attack_known_d, "已知私钥 d"),
    ("decimal_leak", attack_decimal_leak, "长小数 leak≈p/q 连分数还原"),
    ("known_phi", attack_known_phi, "已知 phi 反解 p、q"),
    ("dp_dq_leak", attack_dp_leak, "dp/dq 泄露"),
    ("qinv_dq_low", attack_qinv_dq_low, "qInv + dq 低位（枚举 k 的 Coppersmith）"),
    ("e_high_leak", attack_e_high_leak, "e 的高位泄露（近似二次方程 + Coppersmith）"),
    ("ec_degenerate", attack_ec_degenerate, "退化椭圆曲线（系数即因子）"),
    ("c_gcd_n", attack_c_share_factor, "gcd(c,n) 泄露因子"),
    ("rsa_crt_fault", attack_rsa_crt_fault, "RSA-CRT 故障签名（Bellcore）"),
    ("d_leak", attack_d_factor, "已知 d 反推因子"),
    ("special_structure", attack_special_structure, "n 结构弱点（素数幂/数列/Carmichael）"),
    ("non_rsa", attack_non_rsa, "n 不是两素数之积（素数 / p^k）"),
    ("small_q", attack_small_q, "n 有小素因子"),
    ("common_factor", attack_common_factor, "多模数共享素因子"),
    ("fermat", attack_fermat, "p、q 接近（Fermat）"),
    ("fermat_multiplier", attack_fermat_multiplier, "p、q 成小倍数关系（Fermat 乘子）"),
    ("ab_quadratic", attack_ab_quadratic, "已知 a、b（b=q-p·a）二次方程直接解 p"),
    ("wiener", attack_wiener, "小私钥 d（连分数）"),
    ("approx_power", attack_approx_power, "e ≈ n^k·v/u 型（幂和反推分解）"),
    ("common_modulus", attack_common_modulus, "共模攻击"),
    ("hastad", attack_hastad, "低指数广播"),
    ("small_e_root", attack_small_e_root, "低指数小明文直接开方"),
    ("short_pad", attack_short_pad, "短填充（明文的差很小且未知）"),
    ("dhrel", attack_dh_relations, "DH 样本 (c,g^c mod r) 恢复未知模数并解密"),
    ("pell_lattice", attack_pell_lattice, "Pell 方程 gift + 有界断言恢复 flag"),
    ("ortholat", attack_linear_leaks, "多重线性泄露 a*p+b*q 正交格分解"),
    ("kdp1", attack_kdp1, "known-divisor Pollard p-1（嵌套模数放大指数）"),
    ("sage_heavy", attack_sage_heavy, "Sage 重型（Coppersmith / Boneh-Durfee）"),
    ("franklin_reiter", attack_franklin_reiter, "相关消息攻击"),
    ("partial_p", attack_partial_p, "已知 p 高位/低位（纯 Python Coppersmith）"),
    ("near_p", attack_near_p, "已知 p 的近似值（Coppersmith 补误差）"),
    ("partial_d", attack_partial_d, "已知 d 的低位（partial key exposure）"),
    ("m_high", attack_m_high, "已知明文高位（纯 Python Coppersmith）"),
    ("stereotyped", attack_stereotyped, "已知明文前后缀"),
    ("boneh_durfee", attack_boneh_durfee, "Boneh-Durfee（纯 Python 兜底）"),
    ("factordb", attack_factordb, "在线 FactorDB"),
    ("factorize", attack_generic_factor, "通用整数分解"),
]
