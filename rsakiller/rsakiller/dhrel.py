"""dhrel: 从 (c, C) 对恢复未知 DH 模数 r 并解开其上的离散对数。

攻击面：题目只给出若干对 (c_i, C_i) 与 X/W/n/ct，其中 C_i = g^{c_i} mod r，
而模数 r 本身保密（01_DHRSA 型）。链条：

1. ``recover_r``：对基 [K*c_i | e_i]（K 取 2^(cbits+Cbits+32)）做 LLL，
   零系数行给出精确整数关系 Σλ_i·c_i = 0；代入 C 侧得
   Π C_i^{λ_i} ≡ 1 (mod r)，于是 r | (num − den)。
   对 2~4 条关系取 gcd、剥掉小素因子，要求结果为素数且大于所有输入。
   注意：指数只能是小的 λ（LLL 约减行），绝不能计算 C_i^{c_j} 这类
   512 位指数的精确幂。
2. ``recover_g``：找 gcd(c_i, r−1)=1 的对，g = C_i^{c_i⁻¹ mod (r−1)} mod r，
   并用全部对验证。
3. ``dlog_pohlig_hellman``：给定 r−1 的因子分解，逐素数幂
   BSGS 求 x = log_g h，CRT 合并并回验。
4. ``solve_dhrsa``：整链封装 —— 恢复 r、g，分解 r−1，求 x=log X、
   w=log W，枚举 δ∈{−1,0,1} 与 (t1,t2)∈{0,1}² 拆出 p、q，p·q==n 后解密。

适用输入形态：一组 (指数, g^指数 mod 未知模数) 对（≥3 对，指数与
C 同阶位宽），外加可能存在的 n/ct。判别方法见 ``looks_like_dh_pairs``。
"""
from __future__ import annotations

import time
from math import gcd, isqrt
from typing import Dict, List, Optional, Sequence, Tuple

import gmpy2
from gmpy2 import invert, is_prime, mpz, powmod
from sympy import factorint, isprime
from sympy.polys.domains import ZZ
from sympy.polys.matrices import DomainMatrix
from sympy import Matrix

__all__ = [
    "recover_r", "recover_g", "factor_smooth", "dlog_pohlig_hellman",
    "solve_dhrsa", "looks_like_dh_pairs",
]


def _log(verbose: bool, msg: str) -> None:
    if verbose:
        print(msg, flush=True)


def looks_like_dh_pairs(pairs: Sequence[Tuple[int, int]]) -> bool:
    """启发式判别：(c, C) 对是否像“未知模数上的 DH 泄露”。

    形态特征成对出现且数值同阶：每对里指数与幂的位宽接近（幂 ≈ 模数
    位宽），不同对的指数位宽彼此接近、幂位宽彼此接近，且幂都落在
    [2, 某公共上界) 内（同一模数下的剩余）。命中即可交给 ``recover_r``。
    """
    if len(pairs) < 3:
        return False
    cbits = [int(c).bit_length() for c, _ in pairs]
    Cbits = [int(C).bit_length() for _, C in pairs]
    if min(Cbits) < 8 or any(C <= 1 for _, C in pairs):
        return False
    spread = max(Cbits) - min(Cbits)
    cspread = max(cbits) - min(cbits)
    # 同一模数下的幂位宽应聚在一起（允许个位数抖动）；指数同理。
    return spread <= max(4, min(Cbits) // 8) and cspread <= max(4, min(cbits) // 8)


def recover_r(
    pairs: Sequence[Tuple[int, int]],
    max_lam: int = 5000,
    n_rels: int = 4,
    small_limit: int = 1 << 22,
    verbose: bool = False,
) -> Optional[int]:
    """从 (c, C) 对恢复素模数 r；失败返回 None。

    LLL 找精确零关系 Σλ_i·c_i = 0（丢弃 max|λ| > max_lam 的行，
    否则 num/den 指数过大无法计算）；r | num−den，对前 n_rels 条关系
    逐条累 gcd，每步尝试剥小素因子并检验：素数、大于全部输入、
    且能整除全部关系的 num−den。
    """
    cs = [int(c) for c, _ in pairs]
    Cs = [mpz(C) for _, C in pairs]
    m = len(pairs)
    if m < 3:
        return None
    K = 1 << (max(c.bit_length() for c in cs) + max(C.bit_length() for C in Cs) + 32)
    B = [[0] * (m + 1) for _ in range(m)]
    for i in range(m):
        B[i][0] = K * cs[i]
        B[i][i + 1] = 1

    t0 = time.time()
    red = DomainMatrix.from_Matrix(Matrix(B)).convert_to(ZZ).lll().to_Matrix().tolist()
    _log(verbose, f"[recover_r] LLL dim={m} in {time.time()-t0:.1f}s")

    rels: List[List[int]] = []
    for row in red:
        if int(row[0]) != 0:
            continue
        lam = [int(v) for v in row[1:]]
        if not any(lam) or max(abs(x) for x in lam) > max_lam:
            continue
        if sum(lam[i] * cs[i] for i in range(m)) != 0:
            continue
        rels.append(lam)
    _log(verbose, f"[recover_r] zero-relations={len(rels)}")
    if not rels:
        return None

    def num_den(lam: List[int]) -> Tuple[mpz, mpz]:
        num, den = mpz(1), mpz(1)
        for li, Ci in zip(lam, Cs):
            if li > 0:
                num *= Ci ** li
            elif li < 0:
                den *= Ci ** (-li)
        return num, den

    # num−den 每条关系只算一次（指数上千，幂结果有数百万位），
    # 校验候选 r 时直接取模，绝不在循环里重复计算
    diffs: List[mpz] = []
    for lam in rels:
        num, den = num_den(lam)
        diffs.append(abs(num - den))
    upper = max(cs + [int(C) for C in Cs])

    def strip_small(v: mpz) -> mpz:
        d = mpz(2)
        while d <= small_limit and d * d <= v:
            while v % d == 0:
                v //= d
            d += 1 if d == 2 else 2
        return v

    def try_candidate(g: mpz) -> Optional[int]:
        if g <= 1:
            return None
        v = strip_small(g)
        if v <= 1 or v <= upper:
            return None
        if is_prime(v):
            return int(v)
        # 剥掉小因子后仍是合数（如 r·q'，q' 是另一个大素数）：
        # Pollard rho 拆开，取大于上界的素因子；拆不动则放弃该候选
        w = int(v)
        for _ in range(4):
            rho = _pollard_rho(w, timeout=60.0)
            if not rho:
                break
            other = w // rho
            for cand in (rho, other):
                if cand > upper and is_prime(cand):
                    return int(cand)
            w = min(rho, other)
            if is_prime(w):
                return int(w) if w > upper else None
        return None

    acc = diffs[0]
    seen: List[mpz] = [acc]
    for v in diffs[1:n_rels]:
        acc = gmpy2.gcd(acc, v)
        seen.append(acc)
    # 从最小的候选开始试：原始 num−den 有数百万位，剥离要靠 gcd 中间值；
    # 中间值仍带 ~r·(平滑余量) 的大合数壳（本实例 ~16k bit），剥完即 r
    for g in sorted(seen):
        r = try_candidate(g)
        if r is not None:
            _log(verbose, f"[recover_r] r recovered, {r.bit_length()} bits")
            return r
    return None


def recover_g(pairs: Sequence[Tuple[int, int]], r: int,
              verify: bool = True) -> Optional[int]:
    """已知 r 时恢复生成元 g：用 gcd(c_i, r−1)=1 的对做幂逆，全部对回验。"""
    phi = mpz(r) - 1
    R = mpz(r)
    for c, C in pairs:
        c, C = mpz(int(c)), mpz(int(C))
        if gcd(int(c), int(phi)) != 1:
            continue
        cand = powmod(C, invert(c, phi), R)
        if not verify or all(powmod(cand, mpz(int(cj)), R) == mpz(int(Cj))
                             for cj, Cj in pairs):
            return int(cand)
    return None


def _pollard_rho(n: int, timeout: float) -> Optional[int]:
    """Brent 变体 Pollard rho，带时限；n 为合数时返回任一非平凡因子。"""
    if n % 2 == 0:
        return 2
    if is_prime(n):
        return None
    deadline = time.time() + timeout
    for c in (1, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        y, mm = mpz(2) + c, 128
        g = r = q = 1
        x = ys = y
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(mm, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(int(x) - int(y)) % n
                g = gcd(q, n)
                k += mm
                if time.time() > deadline:
                    return None
            r *= 2
        if g == n:
            while True:
                ys = (ys * ys + c) % n
                g = gcd(abs(int(x) - int(ys)), n)
                if g > 1:
                    break
                if time.time() > deadline:
                    return None
        if 1 < g < n:
            return int(g)
    return None


def factor_smooth(
    m: int,
    limit: int = 1 << 24,
    rho_timeout: float = 90.0,
    verbose: bool = False,
) -> Optional[Dict[int, int]]:
    """分解 r−1 这类平滑整数：factorint 逐级提高试除上限，
    剩余合数交给 Pollard rho（对 ≤40 bit 因子实用）。
    分解不完整时返回 None（PH 需要完整分解）。"""
    fac: Dict[int, int] = {}

    def consume(x: int) -> None:
        nonlocal fac
        stack = [x]
        while stack:
            v = stack.pop()
            if v <= 1:
                continue
            if is_prime(v):
                fac[int(v)] = fac.get(int(v), 0) + 1
                continue
            d = factorint(v, limit=limit)
            prod = 1
            complete = True
            for p, e in d.items():
                if not isprime(p):
                    complete = False
                    break
                prod *= int(p) ** int(e)
            if complete and prod == v:
                for p, e in d.items():
                    fac[int(p)] = fac.get(int(p), 0) + int(e)
                continue
            # factorint 只剥走了小因子：先收下素数部分，合数余量走 rho
            comp = v
            for p, e in d.items():
                if isprime(p):
                    fac[int(p)] = fac.get(int(p), 0) + int(e)
                    comp //= int(p) ** int(e)
            while comp > 1 and not is_prime(comp):
                g = _pollard_rho(comp, rho_timeout)
                if g is None:
                    _log(verbose, f"[factor_smooth] stuck on {comp.bit_length()}-bit composite")
                    fac.clear()
                    return
                stack.append(g)
                stack.append(comp // g)
                comp = 1
            if comp > 1:
                fac[int(comp)] = fac.get(int(comp), 0) + 1

    consume(int(m))
    prod = 1
    for p, e in fac.items():
        prod *= p ** e
    if prod != int(m):
        return None
    return fac


def _bsgs(g: mpz, h: mpz, mod: mpz, order: int) -> Optional[int]:
    """order 阶循环子群里的 BSGS：g^x ≡ h (mod mod)。"""
    m = isqrt(order) + 1
    table = {}
    cur = mpz(1)
    for j in range(m):
        table.setdefault(int(cur), j)
        cur = cur * g % mod
    factor = powmod(g, -m, mod)
    gamma = h
    for i in range(m + 1):
        j = table.get(int(gamma))
        if j is not None:
            return (i * m + j) % order
        gamma = gamma * factor % mod
    return None


def dlog_pohlig_hellman(
    g: int, h: int, r: int, factors: Dict[int, int],
    verbose: bool = False,
) -> int:
    """x = log_g h (mod r)，r 素数、factors = r−1 的完整素因子分解。

    逐素数幂降阶后按位（digit-by-digit）BSGS，CRT 合并，末尾回验。
    """
    R, G, H = mpz(r), mpz(g), mpz(h)
    phi = R - 1
    residues: List[int] = []
    moduli: List[int] = []
    for p in sorted(factors):
        e = factors[p]
        q = mpz(p)
        cof = phi // q ** e
        gg = powmod(G, cof, R)          # 阶 q^e
        hh = powmod(H, cof, R)
        gpe = powmod(gg, q ** (e - 1), R)   # 阶 q
        x = 0
        for k in range(e):
            hk = powmod(hh * powmod(gg, -x, R), q ** (e - 1 - k), R)
            dk = _bsgs(gpe, hk, R, int(p))
            if dk is None:
                raise ValueError(f"BSGS failed for prime {p}")
            x += dk * p ** k
        residues.append(x % p ** e)
        moduli.append(p ** e)
        _log(verbose, f"  dlog mod {p} ({int(p).bit_length()} bits, exp {e}) done")
    # CRT（模数互素，增量合并）
    x, mod = 0, 1
    for res, mi in zip(residues, moduli):
        t = ((res - x) * pow(mod % mi, -1, mi)) % mi
        x += mod * t
        mod *= mi
    x %= int(phi)
    if powmod(G, x, R) != H:
        raise ValueError("dlog verification failed")
    return int(x)


def solve_dhrsa(
    pairs: Sequence[Tuple[int, int]],
    X: int, W: int, n: int, ct: int,
    e: int = 65537,
    verbose: bool = True,
) -> Optional[Dict[str, object]]:
    """01_DHRSA 全链：recover_r → recover_g → factor r−1 → dlog → 拆 p,q → 解密。

    核心关系（mod r）：n ≡ p·q = C_s·W^δ，X^cs·W^t1·... 的组合在四组
    (δ, t1, t2) 下恰好枚举出 p 与 q。dlog 结果按底数缓存，x、w 与三个
    δ 各需一次 PH。
    返回 dict{r,g,x,w,p,q,delta,t1,t2,m}；任何一步失败返回 None。
    """
    t_start = time.time()
    X, W, n, ct = mpz(X), mpz(W), mpz(n), mpz(ct)

    t0 = time.time()
    r = recover_r(pairs, verbose=verbose)
    if r is None:
        _log(verbose, "[solve_dhrsa] recover_r failed")
        return None
    _log(verbose, f"[solve_dhrsa] r = {r}  ({time.time()-t0:.1f}s)")

    t0 = time.time()
    g = recover_g(pairs, r)
    if g is None:
        _log(verbose, "[solve_dhrsa] recover_g failed")
        return None
    _log(verbose, f"[solve_dhrsa] g = {g}  ({time.time()-t0:.1f}s)")

    t0 = time.time()
    factors = factor_smooth(r - 1, verbose=verbose)
    if not factors:
        _log(verbose, "[solve_dhrsa] r-1 factorization incomplete")
        return None
    _log(verbose, f"[solve_dhrsa] r-1 factors "
                  f"{[(p, e) for p, e in sorted(factors.items())]}  ({time.time()-t0:.1f}s)")

    cache: Dict[int, int] = {}

    def dlog(h: mpz) -> int:
        key = int(h)
        if key not in cache:
            cache[key] = dlog_pohlig_hellman(g, int(h), r, factors, verbose=verbose)
        return cache[key]

    t0 = time.time()
    x = dlog(X)
    w = dlog(W)
    _log(verbose, f"[solve_dhrsa] x={x} w={w}  ({time.time()-t0:.1f}s)")

    R = mpz(r)
    Winv, Xinv = invert(W, R), invert(X, R)
    found = None
    t0 = time.time()
    for delta in (-1, 0, 1):
        Cs = n * powmod(Winv, delta, R) % R     # n ≡ Cs·W^δ (mod r)
        cs = dlog(Cs)
        _log(verbose, f"[solve_dhrsa] delta={delta} cs={cs}")
        for t1 in (0, 1):
            for t2 in (0, 1):
                p = Cs * powmod(W, t1, R) * powmod(X, cs, R) % R
                q = powmod(Winv, t2, R) * powmod(Xinv, cs, R) % R
                if p * q == n:
                    found = (int(p), int(q), delta, t1, t2)
                    break
            if found:
                break
        if found:
            break
    _log(verbose, f"[solve_dhrsa] param search  ({time.time()-t0:.1f}s)")
    if not found:
        _log(verbose, "[solve_dhrsa] no (p,q) found")
        return None
    p, q, delta, t1, t2 = found
    d = invert(e, (p - 1) * (q - 1))
    m = pow(ct, d, n)
    _log(verbose, f"[solve_dhrsa] total {time.time()-t_start:.1f}s")
    return {
        "r": int(r), "g": int(g), "x": x, "w": w,
        "p": p, "q": q, "delta": delta, "t1": t1, "t2": t2,
        "m": int(m),
    }
