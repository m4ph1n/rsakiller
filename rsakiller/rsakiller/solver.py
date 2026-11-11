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
    # qinv_dq_low 对 k∈[1,e) 逐个试 LLL，全量很贵（本机 4 进程约 2.6 小时）。
    # 下面三项把这件事变成可控的：可只扫一段、可改并行度。
    qhunt_procs: int = 0                     # 0 = 自动（取 min(4, CPU)，实测 4 路到顶）
    qhunt_k_lo: int = 1
    qhunt_k_hi: int = 0                      # 0 = 用 e（全量）
    qhunt_sec_per_k: float = 0.43            # 单 k 实测耗时，用于执行前估算预算


def _sage_might_run(ctx: RSAContext, opts: Options) -> bool:
    """判断本次求解是否可能触发 Sage。

    与 `attacks.attack_sage_heavy` 的进入条件保持一致：需要 n、e、c 齐全，
    且 `sage_heavy` 未被 only/skip 排除。Boneh-Durfee 与 p 高位等分支都在其中。
    """
    if not (ctx.n and ctx.e and ctx.c is not None):
        return False
    if opts.only and "sage_heavy" not in opts.only:
        # 其它攻击（partial_d / nth_root）也可能用 Sage，但代价低，值得一并预热
        return any(nm in opts.only for nm in ("partial_d", "boneh_durfee", "partial_p"))
    return "sage_heavy" not in opts.skip


def solve(ctx: RSAContext, opts: Optional[Options] = None,
          on_try: Optional[Callable[[str, str], None]] = None,
          on_done: Optional[Callable[[str, float, Optional[A.Result]], None]] = None
          ) -> Optional[A.Result]:
    opts = opts or Options()
    A._SAGE_ENABLED = bool(getattr(opts, "use_sage", True))
    start = time.time()

    # Sage 启动要约 6~10 秒：先偷偷拉起来，让它和前面的纯 Python 攻击重叠。
    # 只有本次确实可能用到重型攻击时才预热（参数齐 + 没被 only/skip 排除），
    # 否则光起一个用不上的 Sage 进程就白等好几秒。
    prewarmed = False
    if A._SAGE_ENABLED and _sage_might_run(ctx, opts):
        from . import sagebridge as SB

        SB.warm_up()
        prewarmed = True

    try:
        res = _run_pipeline(ctx, opts, start, on_try, on_done)
    finally:
        # 没跑出结果又没用上 Sage：把预热的进程收掉，别吊着内存和解释器退出
        if prewarmed and not A._SAGE_CACHE and not A._SAGE_TRIED:
            from . import sagebridge as SB

            SB.cancel_prewarm()
    return res


def _run_pipeline(ctx: RSAContext, opts: Options, start: float,
                  on_try: Optional[Callable[[str, str], None]],
                  on_done: Optional[Callable[[str, float, Optional[A.Result]], None]]
                  ) -> Optional[A.Result]:
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
