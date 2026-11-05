"""命令行入口。"""
from __future__ import annotations

import argparse
import io
import os
import sys
import time
from typing import List, Optional

from . import attacks as A
from . import utils as U
from .ctx import RSAContext, parse_any
from .solver import Options, explain, solve

BANNER = r"""
 ____  ____    _  _____ _  _______ _     _____ ____
|  _ \/ ___|  / \|  ___| |/ /_   _| |   | ____|  _ \
| |_) \___ \ / _ \  _| | ' /  | | | |   |  _| | |_) |
|  _ < ___) / ___ \ |___| . \  | | | |___| |___|  _ <
|_| \_\____/_/   \_\____|_|\_\ |_| |_____|_____|_| \_\
        RSA 通杀器 · 自动识别 + 逐条攻击 + 结果校验
"""


def _read_input(args) -> str:
    """支持多个文件（题目脚本 + 输出数据），按顺序拼接。"""
    files = args.file or []
    if isinstance(files, str):
        files = [files]
    parts = []
    for f in files:
        if f == "-":
            parts.append(sys.stdin.read())
            continue
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                parts.append(fh.read())
        except OSError:
            continue
    return "\n".join(parts)


def _build_ctx(args) -> RSAContext:
    if args.pem:
        from .ctx import from_pubkey_file

        ctx = from_pubkey_file(args.pem)
    else:
        raw = _read_input(args)
        ctx = parse_any(raw) if raw.strip() else RSAContext()
    # 命令行参数优先级最高
    for nm in ("n", "e", "c", "p", "q", "d", "dp", "dq"):
        v = getattr(args, nm, None)
        if v is not None:
            setattr(ctx, nm, v)
    if args.n and args.ns:
        ctx.ns = args.ns
    if args.cs:
        ctx.cs = args.cs
        if ctx.c is None:
            ctx.c = ctx.cs[0]
    elif args.c:
        ctx.cs = [args.c]
    if args.ns and args.cs and len(ctx.ns) == len(ctx.cs):
        es = ctx.es if len(ctx.es) == len(ctx.ns) else [ctx.e or 3] * len(ctx.ns)
        ctx.triples = list(zip(ctx.ns, es, ctx.cs))
    if args.hint is not None:
        ctx.hints["hint"] = args.hint
    return ctx


def _fmt_int(v: int, width: int = 64) -> str:
    s = str(v)
    if len(s) <= width:
        return s
    return s[:width] + f"... ({v.bit_length()} bit)"


def _print_result(ctx: RSAContext, res: A.Result) -> None:
    print()
    print("=" * 72)
    print(f"  命中攻击: {res.attack}")
    print(f"  说明    : {res.detail}")
    print("=" * 72)
    if res.factors:
        for p, k in res.factors.items():
            tag = "" if U.is_probable_prime(p) else "  <- 合数?"
            print(f"  p/q = {_fmt_int(p, 72)}{tag}")
    if res.m is None:
        print("  (无明文)")
        return
    print(f"  m   = {_fmt_int(res.m)}")
    if ctx.n:
        print(f"  hex = 0x{format(res.m % ctx.n, 'x')[:96]}")
    txt = res.text()
    if txt is not None:
        try:
            print(f"  >>> {txt.decode('utf-8', 'replace')}")
        except Exception:
            print(f"  >>> {txt!r}")
    else:
        print("  >>> (明文不是可读文本，可能是杂凑或需要额外解码)")
        print(f"  bytes = {U.long_to_bytes(res.m)[:48]!r}")


def _emit_script(path: str, ctx: RSAContext, res: A.Result) -> None:
    lines = [
        "#!/usr/bin/env python3",
        f'"""由 rsakiller 自动生成 —— 命中攻击: {res.attack}"""',
        "from rsakiller.ctx import RSAContext",
        "from rsakiller.solver import Options, solve",
        "",
        "ctx = RSAContext(",
        f"    n={ctx.n!r},",
        f"    e={ctx.e!r},",
        f"    c={ctx.c!r},",
    ]
    for nm in ("p", "q", "d", "dp", "dq"):
        v = getattr(ctx, nm)
        if v:
            lines.append(f"    {nm}={v!r},")
    if ctx.hints:
        lines.append(f"    hints={ctx.hints!r},")
    if ctx.ns:
        lines.append(f"    ns={ctx.ns!r},")
    if ctx.cs:
        lines.append(f"    cs={ctx.cs!r},")
    lines += [
        ")",
        f"res = solve(ctx, Options(only=['{res.attack}']))",
        "print(hex(res.m) if res else 'failed')",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\n  复现脚本已写入: {path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rsakiller",
        description="CTF RSA 通杀器：贴题面或给参数，自动识别并攻击",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  rsakiller chal.txt                  # 直接喂题面
  cat chal.txt | rsakiller -          # 管道
  rsakiller -n 0x.. -e 65537 -c 0x..  # 手给参数
  rsakiller --pem pub.pem -c 0x..
  rsakiller chal.txt --only wiener,common_modulus -v
""",
    )
    p.add_argument("file", nargs="*", help="题面/数据文件，可给多个（如 main.py output.txt），- 表示 stdin")
    p.add_argument("-n", type=lambda s: int(s, 0), help="模数")
    p.add_argument("-e", type=lambda s: int(s, 0), help="公钥指数")
    p.add_argument("-c", type=lambda s: int(s, 0), help="密文")
    p.add_argument("--p", type=lambda s: int(s, 0))
    p.add_argument("--q", type=lambda s: int(s, 0))
    p.add_argument("--d", type=lambda s: int(s, 0))
    p.add_argument("--dp", type=lambda s: int(s, 0))
    p.add_argument("--dq", type=lambda s: int(s, 0))
    p.add_argument("--ns", type=lambda s: [int(x, 0) for x in s.split(",")], help="多个模数，逗号分隔")
    p.add_argument("--cs", type=lambda s: [int(x, 0) for x in s.split(",")], help="多个密文，逗号分隔")
    p.add_argument("--hint", type=lambda s: int(s, 0), help="题目泄露的数（p 的高位等）")
    p.add_argument("--pem", help="公钥文件（PEM/DER）")
    p.add_argument("--only", help="只跑指定攻击，逗号分隔")
    p.add_argument("--skip", help="跳过指定攻击，逗号分隔")
    p.add_argument("--list", action="store_true", help="列出所有攻击")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-online", action="store_true", help="禁止联网查 FactorDB")
    p.add_argument("--no-bd", action="store_true", help="跳过 Boneh-Durfee（省时间）")
    p.add_argument("--no-sage", action="store_true", help="禁用 Sage，仅用纯 Python")
    p.add_argument("--sage-timeout", type=float, default=900.0, help="Sage 批量任务总超时（秒）")
    p.add_argument("--bd-delta", type=float, default=0.26, help="Boneh-Durfee 的 delta 假设")
    p.add_argument("--max-k", type=int, default=200_000, help="低指数爆破上限 k")
    p.add_argument("--factor-timeout", type=float, default=20.0)
    p.add_argument("--prefix", help="已知明文前缀，如 'flag{'")
    p.add_argument("--unknown-len", type=int, default=0, help="前缀后未知字节数")
    p.add_argument("--m-unknown-bits", type=int, help="已知明文高位时未知的位数")
    p.add_argument("--related", help="相关消息系数 a,b（m2 = a*m1 + b）")
    p.add_argument("--emit", help="把命中方案写成复现脚本")
    p.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    args = build_parser().parse_args(argv)

    if args.list:
        print(f"{'名称':<18}{'说明'}")
        print("-" * 60)
        for name, _fn, desc in A.PIPELINE:
            print(f"{name:<18}{desc}")
        return 0

    ctx = _build_ctx(args)
    # MT19937 题只有密文 + 超长随机数，没有 n；这类题不该被"参数不足"挡掉
    if not ctx.n and not ctx.p and not ctx.ns and not ctx.hints.get("mt_output"):
        print(BANNER)
        print("  没有解析到任何参数。请检查输入，或手动指定 -n/-e/-c。\n")
        print("  已解析到的内容：")
        print(ctx.summary())
        return 2

    opts = Options(
        verbose=args.verbose,
        online=not args.no_online,
        max_k=args.max_k,
        factor_timeout=args.factor_timeout,
        boneh_durfee=not args.no_bd,
        use_sage=not args.no_sage,
        sage_timeout=args.sage_timeout,
        bd_delta=args.bd_delta,
        m_prefix=args.prefix,
        m_unknown_len=args.unknown_len,
        m_unknown_bits=args.m_unknown_bits,
        related=tuple(int(x) for x in args.related.split(",")) if args.related else None,
        only=[s.strip() for s in args.only.split(",")] if args.only else [],
        skip=[s.strip() for s in args.skip.split(",")] if args.skip else [],
    )

    if not args.json:
        print(BANNER)
        print("  解析到的参数:")
        print(ctx.summary())
        if not args.no_sage:
            from . import sagebridge as SB

            info = SB.find_sage()
            if info:
                ver = SB.sage_version()
                print(f"  引擎: Sage{(' ' + ver) if ver else ''}（重型）+ 纯 Python（快速）")
            else:
                print("  引擎: 纯 Python（未找到 Sage，重型攻击会慢很多）")
        print()
        print("  开始尝试攻击…")

    t0 = time.time()

    def on_try(name, desc):
        if not args.json:
            print(f"  [{name}] {desc} ...", end="", flush=True)

    def on_done(name, dt, res):
        if args.json:
            return
        if res and res.m is not None:
            print(f" 命中 ({dt:.2f}s)")
        elif dt > 0.05:
            print(f" 跳过 ({dt:.2f}s)")

    res = solve(ctx, opts, on_try=on_try, on_done=on_done)
    total = time.time() - t0

    if args.json:
        import json

        out = {
            "solved": bool(res and res.m is not None),
            "attack": res.attack if res else None,
            "detail": res.detail if res else None,
            "m": str(res.m) if res and res.m is not None else None,
            "hex": hex(res.m) if res and res.m is not None else None,
            "text": (res.text() or b"").decode("utf-8", "replace") if res else None,
            "elapsed": round(total, 3),
        }
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0 if out["solved"] else 1

    if res and res.m is not None:
        _print_result(ctx, res)
        print(f"\n  总耗时 {total:.2f}s")
        if args.emit:
            _emit_script(args.emit, ctx, res)
        return 0

    print()
    print("=" * 72)
    print("  未命中任何自动攻击")
    print("=" * 72)
    print("  " + explain(ctx, None).replace("\n", "\n  "))
    print(f"\n  总耗时 {total:.2f}s")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
