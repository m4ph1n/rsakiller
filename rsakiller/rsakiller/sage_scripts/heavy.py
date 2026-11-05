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
    inverse_mod, log, exp, GF,
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
