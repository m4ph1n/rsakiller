"""自动调度：按优先级依次尝试所有适用攻击，命中即停。"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import attacks as A
from . import utils as U
from .ctx import RSAContext


@dataclass
class Options:
    verbose: bool = False
    online: bool = True
    max_k: int = 200_000
    factor_timeout: float = 20.0
    boneh_durfee: bool = True
    bd_timeout: float = 120.0
    use_sage: bool = True
    sage_timeout: float = 900.0
    bd_delta: float = 0.26
    m_prefix: Optional[str] = None
    m_suffix: Optional[str] = None
    m_unknown_len: int = 0
    m_unknown_bits: Optional[int] = None
    related: Optional[tuple] = None
    only: List[str] = field(default_factory=list)
    skip: List[str] = field(default_factory=list)
    total_timeout: float = 600.0


def solve(ctx: RSAContext, opts: Optional[Options] = None,
          on_try: Optional[Callable[[str, str], None]] = None,
          on_done: Optional[Callable[[str, float, Optional[A.Result]], None]] = None
          ) -> Optional[A.Result]:
    opts = opts or Options()
    A._SAGE_ENABLED = bool(getattr(opts, "use_sage", True))
    start = time.time()

    # 只给了 p、q 没给 n：直接补全（题目常见写法）
    if ctx.n is None and ctx.p and ctx.q:
        ctx.n = ctx.p * ctx.q
        ctx.notes.append("n 由 p×q 补全")

    if ctx.e == 1 and ctx.c is not None:
        m = ctx.c % ctx.n if ctx.n else ctx.c
        return A.Result("e=1", m, "e 为 1，密文就是明文")

    for name, fn, desc in A.PIPELINE:
        if opts.only and name not in opts.only:
            continue
        if name in opts.skip:
            continue
        if time.time() - start > opts.total_timeout:
            if on_try:
                on_try("timeout", "总超时")
            break
        if on_try:
            on_try(name, desc)
        t0 = time.time()
        res = None
        try:
            res = fn(ctx, opts)
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # 单个攻击崩了不影响其它
            if opts.verbose:
                print(f"    ! {name} 异常: {type(exc).__name__}: {exc}")
            res = None
        dt = time.time() - t0
        if on_done:
            on_done(name, dt, res)
        if res and res.m is not None:
            res.detail = res.detail + f"（{dt:.2f}s）"
            return res
    return None


def explain(ctx: RSAContext, res: Optional[A.Result]) -> str:
    """给出结论 + 失败时的下一步建议。"""
    if res and res.m is not None:
        return ""
    from . import special as SP

    tips = []
    n = ctx.n
    e = ctx.e
    if n:
        tips.append(f"n = {n.bit_length()} bit")
    if e:
        tips.append(f"e = {e if e.bit_length() < 64 else str(e)[:20] + '...'}")
    advice = []
    if n and SP.is_roca_vulnerable(n):
        advice.append("n 落在 ROCA 的小群结构上（CVE-2017-15361），可用 roca 工具专解")
    if n and n.bit_length() >= 1024:
        advice.append("n 较大，常规分解无望 —— 重点看题目有没有额外泄露（dp/dq、p 的高位、d 的大小）")
    if e and n and e > n // 2:
        advice.append("e 接近 n：优先确认是不是小 d 题（Wiener / Boneh-Durfee），或 e 与 phi 不互素")
    if ctx.phi is None and n and n.bit_length() <= 2048 and not advice:
        advice.append("若题面给了 phi，请用 --phi 传入，可直接反解 p、q")
    if not advice:
        advice.append("把完整题面（含所有数字、提示语）贴进来，比只给 n/e/c 更容易命中")
    return " · ".join(tips) + "\n  建议：" + "；".join(advice)
