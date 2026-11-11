"""椭圆曲线：系数泄露 / 退化曲线类攻击。

这一类题的特征是曲线定义在 Z_n 上、而其 Weierstrass 系数**直接就是 n 的因子**
（或与因子有简单关系）。此时曲线在模单个素因子时退化，**任何已知点都能反推出因子**
—— 这是比"分解 n"更便宜的入口。

07_babyRSA_longjian（2025 龙剑杯决赛）是原型：
    E: y² = x³ + p·x + q    over Z_n,  n = p·q
    P = (x, y),  C = e·P,  给出 n, Cx, Cy

关键恒等式（mod p 时 a = p ≡ 0）：
    Cy² − Cx³ ≡ q   (mod p)
即 q ≡ (Cy² − Cx³) mod p。q 比 p 小得多，于是 q 是「模未知因子 p」的小根，
可用 Coppersmith 求出，随后分解 n、分两半还原 P。
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

MAX_EC_ROUNDS = 6


def ec_degenerate_factor(n: int, Cx: int, Cy: int, beta: float = 0.66,
                          extra: int = 48) -> Optional[int]:
    """由退化曲线上的已知点反推 n 的因子（07 型）。

    mod p 时 a = p ≡ 0，曲线退化为 y² = x³ + q，故 q ≡ Cy² − Cx³ (mod p)。
    记 A = (Cy² − Cx³) mod n，则 q 是 f(X) = X − A 模 p 的根。
    Coppersmith 的上界是 n^(β²/δ)，δ=1 ⇒ q < n^(β²)。
    真实场景里较小的那个因子就是 q，取 β = 0.66（≈ 2/3，对应 p:q = 2:1）。

    返回能整除 n 的因子；不适用或无解返回 None。
    """
    A = (Cy * Cy - Cx * Cx * Cx) % n
    # 根的上界按 n^(β²) 估，再多留 extra bit 余量给「因子比假设更小」的情形
    bound_bits = int(beta * beta * n.bit_length()) + extra
    if bound_bits <= 0 or bound_bits > n.bit_length():
        return None
    X = 1 << bound_bits
    # 求 f(X) = X - A 模未知因子的小根：系数取自 (x - A) mod n
    roots = _small_roots_univariate([(-A) % n, 1], n, X=X, beta=beta)
    for r in roots:
        g = _gcd(n, r)
        if 1 < g < n:
            return g
        # 根本身就是因子（X - A 的根 r 满足 r ≡ A mod p ⇒ r ≡ q mod p）
        g = _gcd(n, abs(int(r)) % n)
        if 1 < g < n:
            return g
    return None


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def _small_roots_univariate(coeffs: List[int], N: int, X: int,
                            beta: float = 1.0) -> List[int]:
    """交给 Sage 求单变量小根（纯 Python 的 LLL 在 1535-bit / 高维上不实用）。"""
    from .. import sagebridge as SB

    if not SB.available():
        return []
    res = SB.run_jobs([{"op": "small_roots", "n": str(N),
                        "coeffs": [str(c) for c in coeffs],
                        "X": str(X), "beta": beta}], timeout=600)
    if not res or not res[0].get("ok"):
        return []
    return [int(v) for v in res[0].get("values") or []]


def ec_recover_point(n: int, Cx: int, Cy: int, e: int, p: int, q: int,
                     nbytes: int = 0) -> Dict[str, object]:
    """已知 n = p·q 后，分两半还原 P = e⁻¹·C，再解 CRT 代表元。

    标量乘与模约减可交换，故 C mod p = e·(P mod p) 落在退化曲线
    E_p: y² = x³ + q 上；C mod q 落在 E_q: y² = x³ + p·x 上。
    在各自群阶上求 e 的逆即可得 P mod p、P mod q。

    `nbytes` 是明文的固定字节长度（07 题为 192）。给了就用来解开
    「CRT 代表元 + k·n」的多解：n 只有 1535 bit 而明文 1536 bit，
    原值可能落在 x0 + k·n。
    """
    from .. import sagebridge as SB

    if not SB.available():
        return {}
    res = SB.run_jobs([{"op": "ec_recover", "n": str(n), "Cx": str(Cx),
                        "Cy": str(Cy), "e": int(e), "p": str(p), "q": str(q),
                        "nbytes": int(nbytes)}], timeout=600)
    if not res or not res[0].get("ok"):
        return {}
    return res[0]


FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,12}\{[^}\n]{1,120}\}")


def flag_in_bytes(raw: bytes) -> Optional[bytes]:
    """从解密出的字节里切出 flag（形如 `flag{...}` / `DASCTF{...}`）。"""
    m = FLAG_RE.search(raw)
    return m.group(0) if m else None
