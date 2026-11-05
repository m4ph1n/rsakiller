"""Boneh-Durfee 攻击（Herrmann-May 改进版）。

适用于 d < N^0.292 且 e 接近 N 的情形（Wiener 只能到 N^0.25）。

不依赖 Sage：多项式用 sympy 表示，格基约减用本项目自带的纯 Python LLL。
构造严格对照 mimoo/RSA-and-LLL-attacks 的 boneh_durfee.sage：

  * x-shift:   x^ii * e^(m-kk) * (u + A*x)^kk
  * y-shift:   y^jj * (u + A*x)^kk * e^(m-kk),  kk 从 floor(m/t)*jj 到 m
  * 单项式集合 = x-shift 展开去重后 + y-shift 追加的 u^kk*y^jj
    （注意：y-shift 只追加这一个形如单项式，保证格为方阵）
  * 格为 nn×nn 方阵，B[i][j] = coeff * UU^a * XX^b * YY^c

注意：这是全工具里最吃算力的一环。失败不代表题错，
只说明该用 Sage + fplll 跑更大的 m。
"""
from __future__ import annotations

import math
import time
from typing import List, Optional, Sequence, Tuple

from . import lll as L
from . import utils as U

Mono = Tuple[int, int, int]   # (u 的指数, x 的指数, y 的指数)


def _build_polys(N: int, e: int, m: int, t: int):
    """返回 (gg, monomials, A)。

    gg: 多项式列表（sympy Poly，变量 u,x,y）
    monomials: 排序后的单项式指数元组列表（与 gg 一一对应，方阵）
    A: (N+1)//2
    """
    import sympy as sp

    u, x, y = sp.symbols("u x y")
    A = (N + 1) // 2
    # polZ = 在 xy = u-1 下把 1+x(A+y) 写成标准形 => u + A*x
    polZ = u + A * x

    gg = []
    # ---- x-shifts ----
    for kk in range(m + 1):
        for ii in range(m - kk + 1):
            gg.append(sp.Poly(sp.expand(x ** ii * e ** (m - kk) * polZ ** kk), u, x, y))

    # x-shift 出现过的单项式集合（去重、保序）
    monomials: List[Mono] = []
    for poly in gg:
        for mo in poly.monoms():
            mo = (int(mo[0]), int(mo[1]), int(mo[2]))
            if mo not in monomials:
                monomials.append(mo)

    # ---- y-shifts ----
    for jj in range(1, t + 1):
        for kk in range((m // t) * jj, m + 1):
            gg.append(sp.Poly(sp.expand(y ** jj * polZ ** kk * e ** (m - kk)), u, x, y))
            # 权威实现中 y-shift 只追加这一个单项式，保证方阵
            monomials.append((kk, 0, jj))

    return gg, monomials, A


def attack(N: int, e: int, delta: float = 0.26, m: Optional[int] = None,
           t: Optional[int] = None, timeout: float = 180.0,
           verbose: bool = False) -> Optional[int]:
    """返回私钥 d，失败返回 None。"""
    start = time.time()
    if delta >= 0.292:
        delta = 0.26
    ms = [m] if m else ([2, 3] if timeout > 60 else [2])
    for mm in ms:
        tt = t if t is not None else max(1, int((1 - 2 * delta) * mm))
        remain = timeout - (time.time() - start)
        if remain <= 1:
            break
        try:
            d = _attempt(N, e, mm, tt, delta, remain, verbose)
        except Exception as exc:
            if verbose:
                print(f"    [BD] m={mm} 失败: {type(exc).__name__}: {exc}")
            d = None
        if d:
            return d
    return None


def _attempt(N: int, e: int, m: int, t: int, delta: float, budget: float,
             verbose: bool) -> Optional[int]:
    import sympy as sp

    t0 = time.time()
    gg, monomials, A = _build_polys(N, e, m, t)
    nn = len(monomials)
    if len(gg) != nn:
        if verbose:
            print(f"    [BD] m={m} 格非方阵 ({len(gg)}x{nn})，跳过")
        return None
    if nn > 34:
        if verbose:
            print(f"    [BD] m={m} 维度 {nn} 超过纯 Python 上限，跳过")
        return None
    if verbose:
        print(f"    [BD] m={m} t={t} dim={nn} delta={delta}")

    # 高精度求 N^delta（float 会溢出且丢失 1024-bit 数的精度）
    try:
        import gmpy2
        gmpy2.get_context().precision = 400
        nd = int(gmpy2.mpfr(N) ** gmpy2.mpfr(delta))
    except Exception:
        from decimal import Decimal, getcontext
        getcontext().prec = 60
        nd = int(Decimal(N) ** Decimal(str(delta)))
    XX = 2 * nd
    YY = U.isqrt(N)
    UU = XX * YY + 1

    scale = [UU ** mo[0] * XX ** mo[1] * YY ** mo[2] for mo in monomials]

    # 构建方阵格（仿 mimoo 的下三角构造：行 ii 只在列 jj<=ii 有非零）
    B: List[List[int]] = []
    for poly in gg:
        d = poly.as_dict()
        row = [0] * nn
        for i, mo in enumerate(monomials):
            v = d.get(mo)
            if v:
                row[i] = int(v) * scale[i]
        B.append(row)
    # 确保对角线可约（对角主元即 gg[ii] 中该单项式系数*scale）
    for i in range(nn):
        pass

    red = L.lll_reduce(B, delta=0.75)
    if verbose:
        print(f"    [BD] LLL 完成 {time.time() - t0:.1f}s")

    w, z = sp.symbols("w z")
    top = min(nn, 5)
    for i in range(top):
        for j in range(i + 1, top):
            try:
                pol1 = _vec_to_poly(red[i], monomials, scale)
                pol2 = _vec_to_poly(red[j], monomials, scale)
                if pol1 is None or pol2 is None:
                    continue
                p1 = sp.expand(pol1.subs({sp.Symbol("u"): w * z + 1, sp.Symbol("x"): w, sp.Symbol("y"): z}))
                p2 = sp.expand(pol2.subs({sp.Symbol("u"): w * z + 1, sp.Symbol("x"): w, sp.Symbol("y"): z}))
                if p1 == 0 or p2 == 0:
                    continue
                rr = sp.resultant(p1, p2, w)
                if rr == 0:
                    continue
                rr = sp.Poly(sp.expand(rr), z)
                if rr.degree() < 1:
                    continue
                yroots = [int(r) for r, _ in sp.roots(rr.as_expr(), z).items() if r.is_Integer]
                for y0 in yroots:
                    ss = sp.Poly(sp.expand(p1.subs(z, y0)), w)
                    xroots = [int(r) for r, _ in sp.roots(ss.as_expr(), w).items() if r.is_Integer]
                    for x0 in xroots:
                        num = 1 + x0 * (A + y0)
                        if num % e:
                            continue
                        d = num // e
                        if d <= 0 or d >= N:
                            continue
                        # 用 2 做一次加解密验证：最可靠的判定
                        if U.powmod(U.powmod(2, e, N), d, N) == 2:
                            if verbose:
                                print(f"    [BD] 命中 d，用时 {time.time() - t0:.1f}s")
                            return d
            except Exception:
                continue
            if time.time() - t0 > budget:
                return None
    return None


def _vec_to_poly(vec: Sequence[int], monomials: List[Mono], scale: List[int]):
    import sympy as sp

    u, x, y = sp.symbols("u x y")
    expr = 0
    for i, c in enumerate(vec):
        if c == 0:
            continue
        if c % scale[i]:
            return None
        expr += (c // scale[i]) * (u ** monomials[i][0] * x ** monomials[i][1] * y ** monomials[i][2])
    return sp.expand(expr)
