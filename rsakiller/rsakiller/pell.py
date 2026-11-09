"""Pell 方程 + 3 维格恢复 flag 两半（20_PECO 形态）。

输入形态：题目打印 gift = A*x² − B*y² 且 gift 恰好等于 A 本身，
即 A*(x² − (B//A)*y²) = A ⟺ x² − D·y² = 1（D = B//A，Pell 方程，
有无穷多解）。同时题目断言 (x*f0 + y*f1) % m < residue_bound
（f0, f1 = flag 前后半段的整数值）。于是 (s, f0, f1) = (x*f0+y*f1−t·m, f0, f1)
是格 L = {[x,1,0],[y,0,1],[m,0,0]} 中的短向量，LLL 直接约出。

不含 Sage 依赖：Pell 用连分数/chakravala 迭代，LLL 用 sympy
DomainMatrix（ZZ 域，精确整数）。D 为平方数或 B % A != 0 时抛
ValueError，绝不猜测。
"""
from __future__ import annotations

from math import isqrt
from typing import List, Optional, Tuple

from sympy import Matrix
from sympy.polys.matrices import DomainMatrix
from sympy.polys.domains import ZZ

from . import utils as U


# --------------------------------------------------------------------------
# Pell 基础
# --------------------------------------------------------------------------
def pell_fundamental(D: int) -> Tuple[int, int]:
    """求 x² − D·y² = 1 的最小解（fundamental solution）。

    连分数展开 √D 的收敛子迭代（chakravala 同型），收敛于第 1 个满足
    h² − D·k² = 1 的收敛子。D 必须是正的非平方数，否则 ValueError。
    """
    if not isinstance(D, int) or D <= 0:
        raise ValueError(f"D 必须是正整数，得到 {D!r}")
    a0 = U.isqrt(D)
    if a0 * a0 == D:
        raise ValueError(f"D = {D} 是完全平方数，x² − D·y² = 1 只有平凡解，不是 Pell 方程")
    mm, dd, aa = 0, 1, a0
    hp, hp2 = 1, 0          # h_{-1}=1, h_{-2}=0
    kp, kp2 = 0, 1          # k_{-1}=0, k_{-2}=1
    while True:
        h = aa * hp + hp2
        k = aa * kp + kp2
        if h * h - D * k * k == 1:
            return h, k
        hp2, hp = hp, h
        kp2, kp = kp, k
        mm = dd * aa - mm
        dd = (D - mm * mm) // dd
        aa = (a0 + mm) // dd


def pell_kth(D: int, k: int) -> Tuple[int, int]:
    """求 x² − D·y² = 1 的第 k 个解（k >= 1，k=1 即基本解）。

    在 Z[√D] 中做 (x₁ + y₁·√D)^k 的平方-乘快速幂：
    (a+b√D)(c+d√D) = (ac + D·bd) + (ad + bc)√D。范数 1 在乘法下封闭，
    结果自动满足方程。k <= 0 或 D 非法时 ValueError。
    """
    if k <= 0:
        raise ValueError(f"k 必须 >= 1，得到 {k!r}")
    x1, y1 = pell_fundamental(D)
    rx, ry = 1, 0           # 1 + 0·√D
    bx, by = x1, y1
    while k:
        if k & 1:
            rx, ry = rx * bx + D * ry * by, rx * by + bx * ry
        k >>= 1
        if k:
            bx, by = bx * bx + D * by * by, 2 * bx * by
    assert rx * rx - D * ry * ry == 1
    return rx, ry


# --------------------------------------------------------------------------
# 格恢复 flag 两半
# --------------------------------------------------------------------------
def _lll_rows(rows: List[List[int]]) -> List[List[int]]:
    """sympy DomainMatrix LLL，返回精确 int 矩阵。"""
    dm = DomainMatrix.from_Matrix(Matrix(rows)).convert_to(ZZ)
    return [[int(v) for v in row] for row in dm.lll().to_Matrix().tolist()]


def recover_split(x: int, y: int, m: int,
                  residue_bound: int) -> Tuple[int, int]:
    """由 Pell 解 (x, y) 与断言 (x*f0+y*f1) % m < residue_bound 恢复 f0, f1。

    构造 3 维格 [x,1,0],[y,0,1],[m,0,0]，LLL 后取 |s| 最短且 f0、f1 均非零
    的行 (s, f0, f1)，返回 (abs(f0), abs(f1))。若约减后不存在两半皆非零的
    行，返回 (0, 0)（调用方据此换下一个 Pell 解）。residue_bound 不直接参与
    选行（行内符号不定，abs 后符号组合才对得上），由调用方验证。
    """
    red = _lll_rows([[x, 1, 0], [y, 0, 1], [m, 0, 0]])
    cands = sorted((r for r in red if r[1] != 0 and r[2] != 0),
                   key=lambda r: abs(r[0]))
    if not cands:
        return 0, 0
    _, f0, f1 = cands[0]
    return abs(f0), abs(f1)


def _to_bytes(v: int) -> bytes:
    v = abs(int(v))
    return v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")


def _printable(b: bytes) -> bool:
    return bool(b) and all(32 <= c < 127 for c in b)


# --------------------------------------------------------------------------
# 检测 + 顶层入口
# --------------------------------------------------------------------------
def detect_pell_D(A: int, B: int, V: int) -> int:
    """识别 20_PECO 形态：gift = A·x² − B·y² 且 gift == A ⟹ D = B//A。

    B % A != 0、V != A、D 为平方数均抛 ValueError（fail loud，不猜）。
    """
    if A <= 0 or B <= 0:
        raise ValueError(f"A, B 必须为正，得到 A={A}, B={B}")
    if B % A != 0:
        raise ValueError(f"B % A = {B % A} != 0：B 不是 A 的倍数，gift = A·x² − B·y² "
                         f"无法化为 Pell 方程 x² − D·y² = 1，拒绝猜测")
    if V != A:
        raise ValueError(f"gift = {V} != A = {A}：本模块只处理 gift 恰为 A 的形态"
                         f"（x² − D·y² = 1），其余二次型不在范围内")
    D = B // A
    if U.is_square(D):
        raise ValueError(f"D = B//A = {D} 是完全平方数，不是 Pell 方程，拒绝处理")
    return D


def pell_attack(A: int, B: int, V: int, m: int, residue_bound: int,
                verbose: bool = True) -> Optional[Tuple[int, int, int, int, bytes]]:
    """20_PECO 形态端到端：gift = A·x² − B·y² == A + 断言 (x*f0+y*f1)%m < bound。

    流程：detect_pell_D 检出 D → 扫 k = 1..3 的 Pell 解 → 每个解走
    recover_split → 两半都能解码为可打印 ASCII 才接受。返回
    (x, y, f0, f1, flag_bytes)；无可打印候选返回 None。

    B % A != 0 / V != A / D 平方时直接抛 ValueError（见 detect_pell_D）。
    """
    D = detect_pell_D(A, B, V)
    if verbose:
        print(f"[pell] D = B//A = {D} ({D.bit_length()} bits, nonsquare)")

    best: Optional[Tuple[int, int, int, int, bytes]] = None
    for k in range(1, 4):
        x, y = pell_kth(D, k)
        f0, f1 = recover_split(x, y, m, residue_bound)
        if verbose:
            print(f"[pell] k={k}: x {x.bit_length()} bits, y {y.bit_length()} bits | "
                  f"f0 {f0.bit_length()} bits, f1 {f1.bit_length()} bits")
        if f0 == 0 and f1 == 0:
            if verbose:
                print(f"[pell] k={k}: LLL 无可用行，跳过")
            continue
        b0, b1 = _to_bytes(f0), _to_bytes(f1)
        ok = _printable(b0) and _printable(b1)
        if verbose:
            res = (x * f0 + y * f1) % m
            print(f"[pell] k={k}: b0={b0!r} b1={b1!r} printable={ok} "
                  f"residue={res} (< bound: {res < residue_bound})")
        if ok:
            best = (x, y, f0, f1, b0 + b1)
            break
    if best is None and verbose:
        print("[pell] k=1..3 均未得到可打印的两半，攻击失败")
    return best
