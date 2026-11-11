# -*- coding: utf-8 -*-
"""Sage 侧重型攻击实现。

两种调用方式共用 `run_batch()`：
- 一次性：`sage -python heavy.py task.json result.json`，或经环境变量传路径。
- 常驻：`sage -python heavy.py --serve`，从 stdin 按行读 JSON 请求、向 stdout 写 JSON 响应，
  避免每次任务都重付 Sage 启动成本（本机 Cygwin 版约 6~10 秒）。

任务协议（JSON 数组）：
  {"op": "partial_p", "n": "...", "hint": "...", "unknown_bits": 128, "mode": "high"|"low"}
  {"op": "message_high", "n": "...", "e": 3, "c": "...", "m_high": "...", "unknown_bits": 40}
  {"op": "stereotyped", "n": "...", "e": 3, "c": "...", "prefix": "...", "suffix": "...", "unknown_len": 8}
  {"op": "boneh_durfee", "n": "...", "e": "...", "delta": 0.26, "m": 4}
  {"op": "small_roots", "n": "...", "coeffs": ["...", ...], "X": "...", "beta": 0.5}
  {"op": "ping"}

结果协议（JSON 数组，与任务一一对应）：
  {"ok": true, "value": "..."}  |  {"ok": false, "err": "..."}

常驻协议（每行一个 JSON）：
  请求 {"jobs": [...]}  → 响应 {"ok": true, "results": [...]}
  请求 {"op": "__ping__"} → 响应 {"ok": true, "ready": true}（不触发任何 Sage 计算）
  请求 {"op": "__quit__"} → 退出进程
启动完成后先输出一行 {"ready": true}，调用方据此确认可发任务。
"""
import json
import math
import os
import sys
import time
import traceback

from sage.all import (
    ZZ, QQ, RR, RealField, PolynomialRing, Matrix, Integer,
    floor, ceil, gcd, isqrt, power_mod, IntegerModRing,
    inverse_mod, log, exp, GF, Zmod, EllipticCurve, crt, random_prime,
)
RealFieldHigh = RealField(400)

def _num(v):
    """支持十进制/0x 十六进制字符串与任意整数。"""
    if isinstance(v, str):
        return ZZ(int(v, 0))
    return ZZ(int(v))


# ---------------------------------------------------------------------------
# Coppersmith（Howgrave-Graham 格 + Sage LLL）
#
# 不直接用 Sage 的 f.small_roots()：它在"根接近上界"或 n 为奇数位时
# 经常静默返回空，且参数不可控。这里沿用已验证的格构造，只把 LLL
# 换成 Sage 的 fplll，行为可预测。
# ---------------------------------------------------------------------------
def _poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    out[i + j] += ai * bj
    return out


def _poly_shift(p, k):
    return [0] * k + list(p)


def coppersmith_lll(f_coeffs, N, beta=1.0, X=None, m=None, t=None,
                    epsilon=None, max_dim=80):
    """求 f(x) ≡ 0 (mod b) 的小根，b | N 且 b >= N^beta。返回整数根列表。"""
    N = int(N)
    f = [int(c) % N for c in f_coeffs]
    while len(f) > 1 and f[-1] == 0:
        f.pop()
    delta = len(f) - 1
    if delta <= 0:
        return []
    lc = f[-1] % N
    if not lc:
        return []
    try:
        iv = inverse_mod(lc, N)
    except Exception:
        return []
    f = [(c * int(iv)) % N for c in f]

    if epsilon is None:
        if X is not None and int(X) > 1:
            xr, nr = RealField(200)(int(X)), RealField(200)(N)
            margin = beta ** 2 / delta - float(log(xr) / log(nr))
            if margin <= 1e-6:
                return []
            epsilon = margin * 0.9
        else:
            epsilon = beta / 8.0
    if m is None:
        m = max(1, int(math.ceil(beta ** 2 / (delta * epsilon))))
    if t is None:
        t = max(0, int(math.floor(delta * m * (1.0 / beta - 1))))
    if X is None:
        nr = RealField(200)(N)
        X = int(round(float(exp((beta ** 2 / delta - epsilon) * log(nr)))))
    X = int(X)
    if X < 2:
        return []

    dim = delta * m + t
    if dim > max_dim:
        return []

    basis = []
    fpow = [1]
    for i in range(m):
        Ni = N ** (m - i)
        for j in range(delta):
            p = _poly_shift(fpow[:], j)
            row = [0] * dim
            for d, c in enumerate(p):
                if d < dim:
                    row[d] = c * Ni
            basis.append(row)
        fpow = _poly_mul(fpow, f)
    for i in range(t):
        p = _poly_shift(fpow[:], i)
        row = [0] * dim
        for d, c in enumerate(p):
            if d < dim:
                row[d] = c
        basis.append(row)

    for row in basis:
        for d in range(dim):
            if row[d]:
                row[d] *= X ** d

    B = Matrix(ZZ, basis).LLL()

    R = PolynomialRing(ZZ, names=("x",))
    xr = R.gen()
    found = []
    for i in range(min(10, B.nrows())):
        row = [int(B[i, j]) for j in range(B.ncols())]
        coeffs, ok = [], True
        for d in range(dim):
            xd = X ** d
            if row[d] % xd:
                ok = False
                break
            coeffs.append(row[d] // xd)
        if not ok:
            continue
        g = 0
        for c in coeffs:
            g = int(gcd(g, abs(c)))
        if g > 1:
            coeffs = [c // g for c in coeffs]
        poly = R(0)
        for d, c in enumerate(coeffs):
            if c:
                poly += c * xr ** d
        if poly.degree() < 1:
            continue
        try:
            roots = [int(r) for r, _ in poly.roots() if r in ZZ]
        except Exception:
            roots = []
        for r in roots:
            if r not in found:
                found.append(r)
    return found




# ---------------------------------------------------------------------------
# Coppersmith：已知因子高位 / 低位
# ---------------------------------------------------------------------------
def op_partial_p(job):
    n = int(_num(job["n"]))
    hint = int(_num(job["hint"]))
    unknown = int(job["unknown_bits"])
    shift = 1 << unknown
    mode = job.get("mode", "high")
    beta = float(job.get("beta", 0.5))

    if mode == "high":
        # p = hint * 2^unknown + x
        roots = coppersmith_lll([(hint * shift) % n, 1], n, beta=beta, X=shift)
        for r in roots:
            p = hint * shift + r
            if p > 1 and n % p == 0:
                return {"ok": True, "value": str(p)}
    else:
        # p = x * 2^unknown + hint
        iv = inverse_mod(shift, n)
        if iv is None:
            return {"ok": False, "err": "shift 与 n 不互素"}
        roots = coppersmith_lll([(hint * int(iv)) % n, 1], n, beta=beta, X=shift)
        for r in roots:
            p = r * shift + hint
            if p > 1 and n % p == 0:
                return {"ok": True, "value": str(p)}
    return {"ok": False, "err": "Coppersmith 未给出因子"}


def op_partial_p_low(job):
    """已知 p 的低若干位：p = x·2^k + p_low，用 Coppersmith 补出高位。

    shift 由已知位数决定，X 由未知位数（n 的位宽减去已知位数）决定，
    两者混用会让多项式描述成另一个 p。beta 取 0.49 而非 0.5：真实因子
    可能略小于 √n，用 0.49 才能保证「除数 ≥ N^beta」这个前提不被破坏。
    """
    n = int(_num(job["n"]))
    p_low = int(_num(job["p_low"]))
    known = int(job["known_bits"])
    beta = float(job.get("beta", 0.49))
    pbits = (int(n).bit_length() + 1) // 2
    unknown = pbits - known
    if known <= 0 or unknown <= 0:
        return {"ok": False, "err": "位数不合理"}
    shift = 1 << known
    try:
        iv = int(inverse_mod(shift, n))
    except Exception:
        return {"ok": False, "err": "shift 与 n 不互素"}
    # f(x) = shift·x + p_low 先化首一：乘以 shift^-1
    roots = coppersmith_lll([(p_low * iv) % n, 1], n, beta=beta, X=1 << unknown)
    for r in roots:
        p = r * shift + p_low
        if 1 < p < n and n % p == 0:
            return {"ok": True, "value": str(p)}
    return {"ok": False, "err": "Coppersmith 未给出因子"}


# ---------------------------------------------------------------------------
# Coppersmith：已知明文高位 / 前后缀
# ---------------------------------------------------------------------------
def op_message_high(job):
    n = int(_num(job["n"]))
    e = int(_num(job["e"]))
    c = int(_num(job["c"]))
    mh = int(_num(job["m_high"]))
    ub = int(job["unknown_bits"])
    shift = 1 << ub

    if e > 64:
        return {"ok": False, "err": "e 过大（%d），明文高位 Coppersmith 不适用" % e}
    base = [(mh * shift) % n, 1]
    poly = [1]
    for _ in range(e):
        poly = [x % n for x in _poly_mul(poly, base)]
    poly[0] = (poly[0] - c) % n
    for r in coppersmith_lll(poly, n, beta=1.0, X=shift):
        m = (mh * shift + r) % n
        if power_mod(m, e, n) == c % n:
            return {"ok": True, "value": str(m)}
    return {"ok": False, "err": "Coppersmith 未给出明文"}


def op_stereotyped(job):
    n = int(_num(job["n"]))
    e = int(_num(job["e"]))
    c = int(_num(job["c"]))
    pre = int(job.get("prefix") or 0)
    suf = int(job.get("suffix") or 0)
    ulen = int(job.get("unknown_len", 0))
    slen = int(job.get("suffix_len", 0))

    if e > 64:
        return {"ok": False, "err": "e 过大"}
    shift = 1 << (8 * ulen)
    high = pre * (1 << (8 * (ulen + slen)))
    low = suf
    base = [(high + low) % n, (1 << (8 * slen)) % n]
    poly = [1]
    for _ in range(e):
        poly = [x % n for x in _poly_mul(poly, base)]
    poly[0] = (poly[0] - c) % n
    for r in coppersmith_lll(poly, n, beta=1.0, X=shift):
        m = (high + r * (1 << (8 * slen)) + low) % n
        if power_mod(m, e, n) == c % n:
            return {"ok": True, "value": str(m)}
    return {"ok": False, "err": "Coppersmith 未给出明文"}


# ---------------------------------------------------------------------------
# Boneh-Durfee（Herrmann-May）
# ---------------------------------------------------------------------------
def _remove_unhelpful(BB, monomials, bound, current, dim_min=7):
    if current == -1 or BB.dimensions()[0] <= dim_min:
        return BB
    for ii in range(current, -1, -1):
        if BB[ii, ii] >= bound:
            affected = 0
            idx = 0
            for jj in range(ii + 1, BB.dimensions()[0]):
                if BB[jj, ii] != 0:
                    affected += 1
                    idx = jj
            if affected == 0:
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                return _remove_unhelpful(BB, monomials, bound, ii - 1, dim_min)
            elif affected == 1:
                deeper = True
                for kk in range(idx + 1, BB.dimensions()[0]):
                    if BB[kk, idx] != 0:
                        deeper = False
                if deeper and abs(bound - BB[idx, idx]) < abs(bound - BB[ii, ii]):
                    BB = BB.delete_columns([idx, ii])
                    BB = BB.delete_rows([idx, ii])
                    monomials.pop(idx)
                    monomials.pop(ii)
                    return _remove_unhelpful(BB, monomials, bound, ii - 1, dim_min)
    return BB


def op_boneh_durfee(job):
    N = _num(job["n"])
    e = _num(job["e"])
    delta = float(job.get("delta", 0.26))
    if delta >= 0.292:
        delta = 0.28
    mm = int(job.get("m", 4))
    tt = job.get("t")

    PR = PolynomialRing(ZZ, names=("u", "x", "y"))
    u, x, y = PR.gens()
    A = (N + 1) // 2
    pol = 1 + x * (A + y)

    Q = PR.quotient(x * y + 1 - u)
    polZ = Q(pol).lift()

    XX = 2 * ZZ(floor(RealFieldHigh(N) ** RealFieldHigh(delta)))
    YY = ZZ(N).isqrt()
    UU = XX * YY + 1

    if tt is None:
        tt = max(1, int((1 - 2 * delta) * mm))
    tt = int(tt)

    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            gg.append(x ** ii * e ** (mm - kk) * polZ ** kk)
    gg.sort()

    monomials = []
    for p in gg:
        for mo in p.monomials():
            if mo not in monomials:
                monomials.append(mo)
    monomials.sort()

    for jj in range(1, tt + 1):
        for kk in range((mm // tt) * jj, mm + 1):
            yshift = y ** jj * polZ ** kk * e ** (mm - kk)
            gg.append(Q(yshift).lift())

    for jj in range(1, tt + 1):
        for kk in range((mm // tt) * jj, mm + 1):
            monomials.append(u ** kk * y ** jj)

    nn = len(monomials)
    if len(gg) != nn:
        return {"ok": False, "err": "格非方阵 %d x %d" % (len(gg), nn)}
    if nn > 60:
        return {"ok": False, "err": "纬度 %d 过大" % nn}

    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU, XX, YY)

    try:
        BB = _remove_unhelpful(BB, monomials, e ** mm, nn - 1)
    except Exception:
        pass
    nn = BB.dimensions()[0]
    if nn == 0:
        return {"ok": False, "err": "remove_unhelpful 删空"}

    det = BB.det()
    bound = e ** (mm * nn)
    det_ok = det < bound

    BB = BB.LLL()

    PR2 = PolynomialRing(ZZ, names=("w", "z"))
    w, z = PR2.gens()

    found = False
    rr = None
    pol1 = pol2 = None
    for i in range(nn - 1):
        for j in range(i + 1, nn):
            p1 = PR2(0)
            p2 = PR2(0)
            ok1 = ok2 = True
            for k in range(nn):
                s = monomials[k](UU, XX, YY)
                if s == 0:
                    ok1 = ok2 = False
                    break
                q = int(BB[i, k]) // int(s)
                r = int(BB[j, k]) // int(s)
                p1 += q * monomials[k](w * z + 1, w, z)
                p2 += r * monomials[k](w * z + 1, w, z)
            if not (ok1 and ok2) or p1 == 0 or p2 == 0:
                continue
            try:
                rres = p1.resultant(p2, w)
            except Exception:
                continue
            if rres == 0:
                continue
            rp = PR2(rres).univariate_polynomial()
            if rp.degree() < 1:
                continue
            try:
                yroots = [r for r, _ in rp.roots() if r in ZZ]
            except Exception:
                yroots = []
            for y0 in yroots:
                try:
                    ss = PR2(p1(w, y0))
                    xroots = [r for r, _ in ss.univariate_polynomial().roots() if r in ZZ]
                except Exception:
                    xroots = []
                for x0 in xroots:
                    num = 1 + int(x0) * (int(A) + int(y0))
                    if num <= 0 or num % int(e) != 0:
                        continue
                    d = num // int(e)
                    if d <= 0 or d >= int(N):
                        continue
                    if power_mod(2, int(e) * d, int(N)) == 2:
                        return {"ok": True, "value": str(d), "dim": nn, "det_ok": bool(det_ok)}
            if found:
                break
    return {"ok": False, "err": "LLL 后未找到 d（dim=%d, det_ok=%s）" % (nn, det_ok)}


# ---------------------------------------------------------------------------
# qInv + dq 低位：CISCN2024 ez_rsa / checkin 型
#
# pycryptodome 导出 DER 的末尾 INTEGER 是 qInv = q^{-1} mod p。
# 由 e·dq ≡ 1 (mod q-1) 得 e·dq - 1 = k·(q-1)，k ∈ [1,e)。
# 记 A = e·dq - 1 + k = k·q，则
#     qInv·A² - k·A = k²·q·(qInv·q - 1) ≡ 0  (mod n)
# 因为 qInv·q - 1 ≡ 0 (mod p)、A ≡ 0 (mod q)，两个因子各被 p、q 整除。
# 令 dq = 2^L·x + dq_low，则 x = dq >> L 是 f 在模 n 下的小根；
# deg=2、beta=1 ⇒ 上界 n^{1/2}，L=48 时未知量仅 n^{1/2}/2^48，余量充足。
# k 不能从公开量直接定出，逐个试；命中判据是 q = (e·dq-1)/k + 1 整除 n。
# ---------------------------------------------------------------------------
def _qhunt_basis(n, e, qinv, dq_low, L, k, m, t, X):
    """f(x) = qInv·A² − k·A，A = e·(2^L·x + dq_low) − 1 + k，未知量 x = dq >> L。

    真值时 A = k·q，故 A ≡ 0 (mod q)；又 qInv·A − k = k·(qInv·q − 1) ≡ 0 (mod p)。
    于是 f = A·(qInv·A − k) 被 p、q 各自整除 ⇒ f ≡ 0 (mod n)。

    返回 (基, 维数)；首项在模 n 下不可逆时返回 None（这个 k 直接跳过）。
    """
    S = e * (ZZ(2) ** L)
    B = e * dq_low - 1 + k
    f = [(ZZ(qinv) * B * B - k * B) % n,
         (2 * ZZ(qinv) * S * B - k * S) % n,
         (ZZ(qinv) * S * S) % n]
    try:
        iv = inverse_mod(f[-1], n)
    except Exception:
        return None
    f = [(c * iv) % n for c in f]
    dim = 2 * m + t
    basis = []
    fpow = [ZZ(1)]
    for i in range(m):
        Ni = n ** (m - i)
        for j in range(2):
            row = [ZZ(0)] * dim
            for d, cc in enumerate([ZZ(0)] * j + list(fpow)):
                if d < dim:
                    row[d] = cc * Ni
            basis.append(row)
        nf = [ZZ(0)] * (len(fpow) + len(f) - 1)
        for a_, xa in enumerate(fpow):
            for b_, xb in enumerate(f):
                nf[a_ + b_] += xa * xb
        fpow = nf
    for i in range(t):
        row = [ZZ(0)] * dim
        for d, cc in enumerate([ZZ(0)] * i + list(fpow)):
            if d < dim:
                row[d] = cc
        basis.append(row)
    for row in basis:
        for d in range(dim):
            if row[d]:
                row[d] *= X ** d
    return basis, dim


def _qhunt_reduce(basis):
    """优先用 fpylll（比 Sage 的 Matrix.LLL 快约 1.5 倍），没有则退回 Sage。"""
    try:
        from fpylll import IntegerMatrix, LLL as _FLLL
    except Exception:
        _FLLL = None
    if _FLLL is not None:
        M = IntegerMatrix.from_matrix([[int(v) for v in row] for row in basis])
        _FLLL.reduction(M, delta=0.75)
        return [[ZZ(M[i, j]) for j in range(M.ncols)] for i in range(M.nrows)]
    return Matrix(ZZ, basis).LLL()


def _qhunt_check(red, dim, X, e, dq_low, L, k, n):
    """从约减后的行里取出小根，检验能否还原整除 n 的 q。

    red 是行列表（`_qhunt_reduce` 统一返回 list，不用矩阵以免混淆
    Sage 矩阵没有 __len__ 的坑）。
    """
    R = PolynomialRing(ZZ, names=("z",))
    z = R.gen()
    for i in range(min(6, len(red))):
        row = red[i]
        coeffs, ok = [], True
        for d in range(dim):
            xd = X ** d
            if row[d] % xd:
                ok = False
                break
            coeffs.append(row[d] // xd)
        if not ok:
            continue
        g = ZZ(0)
        for cc in coeffs:
            g = gcd(g, abs(cc))
        if g > 1:
            coeffs = [c // g for c in coeffs]
        pl = R(0)
        for d, cc in enumerate(coeffs):
            if cc:
                pl += cc * z ** d
        if pl.degree() < 1:
            continue
        try:
            roots = [r for r, _ in pl.roots() if r in ZZ]
        except Exception:
            continue
        for r in roots:
            dq = (int(r) << L) + int(dq_low)
            num = int(e) * dq - 1
            if num % k:
                continue
            q = num // k + 1
            if q > 1 and n % q == 0:
                return q
    return None


def op_qhunt(job):
    """枚举 k 区间，返回命中的 (k, q)。

    区间由调用方分片传入，便于多进程并行；这里只跑一个连续段。

    前置裁剪：由 e·dq_low - 1 ≡ k·(q-1) (mod 2^L) 得 v2(k) <= v2(e·dq_low-1)，
    因为 q-1 是偶数会把 v2 抬得更高，不可能压低。几乎一半的 k 可直接排除。
    """
    n = int(_num(job["n"]))
    e = int(_num(job["e"]))
    qinv = int(_num(job["qinv"]))
    dq_low = int(_num(job["dq_low"]))
    L = int(job.get("L", 0)) or max(1, int(dq_low).bit_length())
    k_lo = int(job.get("k_lo", 1))
    k_hi = int(job.get("k_hi", e))
    m = int(job.get("m", 5))
    t = int(job.get("t", 1))
    half = (int(n).bit_length() + 1) // 2
    if half <= L:
        return {"ok": False, "err": "dq 已知位数 %d 不小于半个 n（%d bit）" % (L, half)}
    X = ZZ(2) ** (half - L)
    if half - L >= half:
        return {"ok": False, "err": "dq 只知 %d bit，未知量不小于半个 n（%d bit），Coppersmith 不可行"
                % (L, half)}

    v2_bound = ((e * dq_low - 1) & -(e * dq_low - 1)).bit_length() - 1
    tried = 0
    for k in range(max(1, k_lo), int(k_hi)):
        if (k & -k).bit_length() - 1 > v2_bound:
            continue                # v2(k) 超过上界，必不可能
        tried += 1
        got = _qhunt_basis(ZZ(n), e, qinv, dq_low, L, k, m, t, X)
        if got is None:
            continue                # 首项不可逆，这个 k 无解
        basis, dim = got
        q = _qhunt_check(_qhunt_reduce(basis), dim, X, e, dq_low, L, k, ZZ(n))
        if q:
            return {"ok": True, "value": str(q), "k": k, "tried": tried}
    return {"ok": False, "err": "区间 %d..%d 内未命中（实试 %d 个）" % (k_lo, k_hi, tried)}


# ---------------------------------------------------------------------------
# 高位泄露的 e（CISCN2024 OvO 型）：e = f(p, q) 且低若干位被清零
#
# 题面把 e 的低 leak_bits 位抹零后才给出。以 OvO 为例：
#     e = 65537 + kk·p + (kk+2)·((p+1)(q+1)) + 1
#       = (kk+2)·n + (2kk+2)·p + (kk+2)·q + (kk+65540)
# 首项给出 kk+2 ≈ e // n，于是 kk 已知。两边乘 p 并用 n = pq 消去 q：
#     e·p = (2kk+2)·p² + (kk+2)·n + a·p，  a = (kk+2)·n + kk + 65540
# 即 (2kk+2)p² + (a−e)p + (kk+2)n = 0，关于 p 的一元二次方程。
# 直接解出的 p 不是整数（e 的低位被抹掉了），但真 p 与它只差 O(2^leak/n)，
# 把它当 Coppersmith 初值即可补足。
# ---------------------------------------------------------------------------
def op_high_leak_quadratic(job):
    """解近似二次方程取 p 的高位，再用 Coppersmith 补足被抹掉的低位。

    仅适用于「e 由 p、q 线性/二次组合而成、且低若干位被整体清零」的题型；
    不是这类结构时 e//n-2 <= 0，直接拒绝。
    """
    n = int(_num(job["n"]))
    e_given = int(_num(job["e"]))
    c = int(_num(job["c"]))
    leak_bits = int(job.get("leak_bits", 0))
    if leak_bits <= 0:
        return {"ok": False, "err": "未给出 e 被抹零的位数"}
    kk = e_given // n - 2
    if kk <= 0:
        return {"ok": False, "err": "e // n - 2 = %d，不符合该题型的结构" % kk}

    A2 = 2 * kk + 2
    B1 = (65537 + (kk + 2) * n + (kk + 2) + 1) - e_given
    C0 = (kk + 2) * n
    disc = ZZ(B1) * B1 - 4 * ZZ(A2) * C0
    if disc <= 0:
        return {"ok": False, "err": "判别式非正，方程无实根"}

    # 精度必须盖过 n 的位宽：默认 RR 只有 53 bit，算出来的近似根是垃圾
    RF = RealField(max(512, int(n).bit_length() + 128))
    sq = RF(disc).sqrt()
    p_found = None
    for sign in (-1, 1):
        p_est = (-RF(B1) + sign * sq) / (2 * RF(A2))
        if p_est <= 0:
            continue
        p_int = int(p_est)
        # 误差来自被抹掉的 leak_bits 位，再经方程放大；给几档余量逐级放大
        for slack in (2, 8, 16, 32):
            X = ZZ(2) ** (leak_bits + slack)
            for r in coppersmith_lll([p_int % n, 1], n, beta=0.5, X=X):
                for cand in (p_int + int(r), p_int + int(r) + 1, p_int + int(r) - 1):
                    if cand > 1 and n % cand == 0:
                        p_found = cand
                        break
                if p_found:
                    break
            if p_found:
                break
        if p_found:
            break
    if not p_found:
        return {"ok": False, "err": "近似解 + Coppersmith 未恢复 p"}

    q = n // p_found
    # 真实 e 由题面公式回代得到，用它验证 leak_bits 猜得对不对
    e_full = 65537 + kk * p_found + (kk + 2) * ((p_found + 1) * (q + 1)) + 1
    if (e_full >> leak_bits) << leak_bits != e_given:
        return {"ok": False, "err": "回代 e 与题面高位不一致，leak_bits 可能不对"}
    try:
        d = inverse_mod(e_full, (p_found - 1) * (q - 1))
    except Exception:
        return {"ok": False, "err": "e 与 phi 不互素"}
    return {"ok": True, "value": str(int(power_mod(c, d, n))),
            "p": str(p_found), "e_full": str(e_full)}


# ---------------------------------------------------------------------------
# 退化椭圆曲线：已知点反推因子 + 分两半还原标量积的原像（07_babyRSA 型）
#
# 曲线 E: y² = x³ + p·x + q over Z_n，系数**就是** n 的两个因子。
# mod p 时 a = p ≡ 0 ⇒ 退化成 y² = x³ + q，于是 Cy² − Cx³ ≡ q (mod p)。
# 这就是"已知 A ≡ q (mod p)、q 比 p 小"的小根问题，Coppersmith 直接给出 q。
# ---------------------------------------------------------------------------
def op_ec_factor(job):
    """由退化曲线上的一点 (Cx, Cy) 求 n 的因子。

    mod p 时 a = p ≡ 0，曲线退化为 y² = x³ + q，故 q ≡ Cy² − Cx³ (mod p)。
    记 A = Cy² − Cx³，则 q 是 f(X) = X − A 模 p 的根，且 q 约为 p 的一半位宽。

    这里用 Sage 原生的 `small_roots`，不用本模块的 `coppersmith_lll`：
    后者是自定义的 Howgrave-Graham 构造，即使 margin 为正也常返回空；
    而 `small_roots` 在同样的 (beta, X) 下稳定命中（本机实测 07 题 6 秒）。
    """
    n = int(_num(job["n"]))
    Cx = int(_num(job["Cx"]))
    Cy = int(_num(job["Cy"]))
    beta = float(job.get("beta", 0.66))
    extra = int(job.get("extra_bits", 16))

    A = (Cy * Cy - Cx * Cx * Cx) % n
    bound_bits = int(beta * beta * int(n).bit_length()) + extra
    if bound_bits <= 0 or bound_bits >= int(n).bit_length():
        return {"ok": False, "err": "上界 %d bit 不合理" % bound_bits}
    X = ZZ(2) ** bound_bits

    PR = PolynomialRing(Zmod(n), names=("X",))
    Xr = PR.gen()
    f = (Xr - ZZ(A)).monic()
    try:
        roots = f.small_roots(X=X, beta=beta)
    except Exception as exc:
        return {"ok": False, "err": "small_roots: %s" % exc}
    for r in roots:
        r = int(r) % n
        g = int(gcd(ZZ(r), ZZ(n)))
        if 1 < g < n:
            return {"ok": True, "value": str(g), "root_bits": int(r).bit_length()}
    return {"ok": False, "err": "small_roots 未给出因子（beta=%.2f, X=2^%d）"
            % (beta, bound_bits)}


def op_ec_recover(job):
    """已知 n=p·q 后还原 P = e⁻¹·C 的横坐标，并解开 CRT 代表元的多解。

    标量乘与模约减可交换：C mod p = e·(P mod p) 在 E_p: y²=x³+q 上；
    C mod q = e·(P mod q) 在 E_q: y²=x³+p·x 上。各自求 e 的逆即可。
    `nbytes` 给出明文固定字节长度时，返回所有 x0 + k·n 落在该长度内的候选。
    """
    n = int(_num(job["n"]))
    Cx = int(_num(job["Cx"]))
    Cy = int(_num(job["Cy"]))
    e = int(_num(job["e"]))
    p = int(_num(job["p"]))
    q = int(_num(job["q"]))
    nbytes = int(job.get("nbytes", 0) or 0)
    if p * q != n:
        return {"ok": False, "err": "p·q != n"}

    Ep = EllipticCurve(GF(p), [0, ZZ(q) % p])       # a = p ≡ 0
    Eq = EllipticCurve(GF(q), [ZZ(p) % q, 0])       # b = q ≡ 0
    Np, Nq = int(Ep.order()), int(Eq.order())
    if gcd(e, ZZ(Np)) != 1 or gcd(e, ZZ(Nq)) != 1:
        return {"ok": False, "err": "e 与群阶不互素（|E_p|=%d, |E_q|=%d）" % (Np, Nq)}

    try:
        Pp = inverse_mod(e, Np) * Ep(ZZ(Cx) % p, ZZ(Cy) % p)
        Pq = inverse_mod(e, Nq) * Eq(ZZ(Cx) % q, ZZ(Cy) % q)
        xp, yp = int(Pp.xy()[0]), int(Pp.xy()[1])
        xq, yq = int(Pq.xy()[0]), int(Pq.xy()[1])
    except Exception as exc:
        return {"ok": False, "err": "还原点失败: %s" % exc}

    x0 = int(crt([ZZ(xp), ZZ(xq)], [ZZ(p), ZZ(q)]))
    Y = int(crt([ZZ(yp), ZZ(yq)], [ZZ(p), ZZ(q)]))

    # 独立校验：e·P 必须回到 C，否则说明还原错了
    try:
        E = EllipticCurve(Zmod(n), [ZZ(p) % n, ZZ(q) % n])
        if e * E(ZZ(x0), ZZ(Y)) != E(ZZ(Cx), ZZ(Cy)):
            return {"ok": False, "err": "e·P != C，还原结果未通过校验"}
    except Exception as exc:
        return {"ok": False, "err": "校验失败: %s" % exc}

    cands = []
    if nbytes > 0:
        limit = 1 << (8 * nbytes)
        cur = x0
        while cur < limit and len(cands) < 64:
            cands.append(cur)
            cur += n
    else:
        cands.append(x0)
    return {"ok": True, "x0": str(x0), "y": str(Y), "candidates": [str(c) for c in cands]}


def op_ec_make_instance(job):
    """生成一道「退化曲线」合成题（供 selftest 用）。

    E: y² = x³ + p·x + q over Z_n，p、q 位宽比 2:1，C = e·P。
    返回 n、C 的坐标、以及与明文对应的字节串。
    """
    import random

    pbits = int(job.get("pbits", 256))
    qbits = int(job.get("qbits", 128))
    msg = str(job.get("msg", "flag{ec_synthetic}")).encode()
    nbytes = int(job.get("nbytes", 64))
    if nbytes < len(msg):
        return {"ok": False, "err": "nbytes 小于 flag 长度"}
    e = int(job.get("e", 65537))

    p = Integer(random_prime(2 ** pbits, lbound=2 ** (pbits - 1)))
    q = Integer(random_prime(2 ** qbits, lbound=2 ** (qbits - 1)))
    n = p * q
    x = Integer(int.from_bytes(msg + bytes(random.getrandbits(8) for _ in range(nbytes - len(msg))), "big"))

    E = EllipticCurve(Zmod(n), [p % n, q % n])
    Ep = EllipticCurve(GF(p), [0, q % p])
    Eq = EllipticCurve(GF(q), [p % q, 0])
    for _ in range(512):
        try:
            yp = Ep.lift_x(Integer(x % p)).xy()[1]
            yq = Eq.lift_x(Integer(x % q)).xy()[1]
            C = e * E(Integer(x), int(crt([Integer(yp), Integer(yq)], [p, q])))
            return {"ok": True, "n": str(int(n)), "Cx": str(int(C[0])),
                    "Cy": str(int(C[1])), "msg": msg.decode("latin-1")}
        except Exception:
            x += 1
    return {"ok": False, "err": "未找到可用的 x"}


# ---------------------------------------------------------------------------
# 通用单变量小根
# ---------------------------------------------------------------------------
def op_small_roots(job):
    n = int(_num(job["n"]))
    coeffs = [int(_num(c)) for c in job["coeffs"]]
    X = int(_num(job["X"])) if job.get("X") else None
    beta = float(job.get("beta", 1.0))
    eps = job.get("epsilon")
    roots = coppersmith_lll(coeffs, n, beta=beta,
                            X=X, epsilon=float(eps) if eps is not None else None)
    if not roots:
        return {"ok": False, "err": "无小根"}
    return {"ok": True, "values": [str(r) for r in roots]}


# ---------------------------------------------------------------------------
# 模素数开任意次方（e | p-1 时纯 Python 实现会放弃，这里用 Sage 补上）
# ---------------------------------------------------------------------------
def op_nth_root(job):
    a = int(_num(job["a"]))
    n_exp = int(_num(job["e"]))
    p = int(_num(job["p"]))
    try:
        R = GF(p)
        roots = R(a).nth_root(n_exp, all=True)
    except Exception as exc:
        return {"ok": False, "err": "nth_root: %s" % exc}
    vals = [str(int(x)) for x in roots]
    if not vals:
        return {"ok": False, "err": "无 n 次根"}
    return {"ok": True, "values": vals}


# ---------------------------------------------------------------------------
# Franklin-Reiter：相关消息
# ---------------------------------------------------------------------------
def op_franklin_reiter(job):
    n = _num(job["n"])
    e = int(_num(job["e"]))
    c1 = _num(job["c1"])
    c2 = _num(job["c2"])
    a = ZZ(int(job.get("a", 1)))
    b = ZZ(int(job.get("b", 1)))

    R = PolynomialRing(IntegerModRing(n), names=("x",))
    x = R.gen()
    g1 = x ** e - c1
    g2 = (a * x + b) ** e - c2
    try:
        h = g1.resultant(g2, x).univariate_polynomial()
    except Exception as exc:
        return {"ok": False, "err": "resultant: %s" % exc}
    if h == 0:
        return {"ok": False, "err": "resultant 退化"}
    try:
        roots = h.roots()
    except Exception:
        roots = []
    for r, _ in roots:
        if r in ZZ:
            m = ZZ(r) % n
            if power_mod(m, e, n) == c1 % n:
                return {"ok": True, "value": str(int(m))}
    return {"ok": False, "err": "未找到共同根"}


# ---------------------------------------------------------------------------
# 整数分解（Sage 的 PARI/ECM，远强于纯 Python 的 rho）
# ---------------------------------------------------------------------------
def op_factor(job):
    n = int(_num(job["n"]))
    try:
        f = ZZ(n).factor()
    except Exception as exc:
        return {"ok": False, "err": "factor: %s" % exc}
    return {"ok": True, "factors": [[str(p), int(e)] for p, e in f]}


OPS = {
    "ping": lambda job: {"ok": True, "value": "pong"},
    "partial_p": op_partial_p,
    "partial_p_low": op_partial_p_low,
    "message_high": op_message_high,
    "stereotyped": op_stereotyped,
    "boneh_durfee": op_boneh_durfee,
    "qhunt": op_qhunt,
    "high_leak_quadratic": op_high_leak_quadratic,
    "ec_factor": op_ec_factor,
    "ec_recover": op_ec_recover,
    "ec_make_instance": op_ec_make_instance,
    "small_roots": op_small_roots,
    "franklin_reiter": op_franklin_reiter,
    "nth_root": op_nth_root,
    "factor": op_factor,
}


def run_batch(jobs):
    """顺序执行一批任务，返回与输入一一对应的结果列表。

    单个任务抛异常只标记该任务失败，不影响同批其它任务。
    """
    out = []
    for job in jobs:
        op = job.get("op", "")
        fn = OPS.get(op)
        t0 = time.time()
        if fn is None:
            out.append({"ok": False, "err": "未知 op: %s" % op, "op": op})
            continue
        try:
            r = fn(job)
        except Exception:
            r = {"ok": False, "err": traceback.format_exc(limit=3)}
        r["op"] = op
        # 注意：Sage 的 round 返回 RealDoubleElement，必须显式转 float 才能 JSON 序列化
        r["secs"] = float(round(float(time.time() - t0), 2))
        out.append(r)
    return out


def serve():
    """常驻模式：按行收发 JSON，Sage 只启动并初始化一次。"""
    try:
        from sage.version import version as sage_version
    except Exception:
        sage_version = ""
    sys.stdout.write(json.dumps({"ready": True, "sage_version": str(sage_version)}) + "\n")
    sys.stdout.flush()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as exc:
            sys.stdout.write(json.dumps({"ok": False, "err": "JSON 解析失败: %s" % exc}) + "\n")
            sys.stdout.flush()
            continue
        op = msg.get("op")
        if op == "__quit__":
            return 0
        if op == "__ping__":
            sys.stdout.write(json.dumps({"ok": True, "ready": True}) + "\n")
            sys.stdout.flush()
            continue
        results = run_batch(msg.get("jobs") or [])
        sys.stdout.write(json.dumps({"ok": True, "results": results}) + "\n")
        sys.stdout.flush()
    return 0


def main():
    if "--serve" in sys.argv[1:]:
        return serve()
    task_path = sys.argv[1] if len(sys.argv) >= 3 else os.environ.get("RSAKILLER_TASK", "")
    res_path = sys.argv[2] if len(sys.argv) >= 3 else os.environ.get("RSAKILLER_RESULT", "")
    if not task_path or not res_path:
        print("usage: heavy.py task.json result.json (or set RSAKILLER_TASK/RESULT)", file=sys.stderr)
        return 2
    with open(task_path, "r", encoding="utf-8") as f:
        jobs = json.load(f)
    out = run_batch(jobs)
    with open(res_path, "w", encoding="utf-8") as f:
        json.dump(out, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
