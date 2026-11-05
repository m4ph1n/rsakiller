"""题面解析 + RSA 参数上下文。

目标：把一段乱七八糟的题目描述（或 JSON）变成结构化的 RSAContext，
自动识别哪些参数存在、哪些线索可用。
"""
from __future__ import annotations

import json
import re
import sys as _sys

# CTF 题面常出现上万位十进制数，Python 3.11+ 默认限制 4300 位
try:
    _sys.set_int_max_str_digits(0)
except Exception:
    pass
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import utils as U


# 参数名归一化表：小写后的各种写法 -> 标准名
_NAME_MAP = {
    "n": "n", "nn": "n", "modulus": "n", "mod": "n", "nl": "n",
    "e": "e", "ee": "e", "exp": "e", "exponent": "e", "pubexp": "e",
    "c": "c", "cc": "c", "ct": "c", "cipher": "c", "ciphertext": "c", "enc": "c",
    "p": "p", "pp": "p", "prime1": "p",
    "q": "q", "qq": "q", "prime2": "q",
    "d": "d", "dd": "d", "priv": "d", "privkey": "d", "private": "d",
    "dp": "dp", "dq": "dq", "d_p": "dp", "d_q": "dq", "dmp1": "dp", "dmq1": "dq",
    "phi": "phi", "phin": "phi", "phip": "phi", "varphi": "phi", "fn": "phi",
    "hint": "hint", "leak": "leak", "high": "hint", "p_high": "hint",
    "ph": "hint", "leak_p": "hint", "hp": "hint", "pbar": "hint",
    "m": "m", "flag": "m", "msg": "m", "message": "m",
    "flag_ct": "c", "flagciphertext": "c", "flag_ciphertext": "c",
    "hint_ct": "hint_ct", "hintciphertext": "hint_ct", "hint_ciphertext": "hint_ct",
    "x": "x", "y": "y",
}

_NUM = r"(?:0[xX][0-9a-fA-F_]+[lL]?|\d[\d_]*[lL]?)"
_ASSIGN_RE = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z_0-9]*)\s*(?:=|:|:=)\s*(" + _NUM + r")")
_SHIFT_RE = re.compile(r"([A-Za-z_][A-Za-z_0-9]*)\s*>>\s*(\d+)")
_LIST_RE = re.compile(r"([A-Za-z_][A-Za-z_0-9]*)\s*=\s*\[([^\]]*)\]")

# 题目常把 print 输出直接贴进来，形如 ('n=', '0x1234...') 或 ("n=", "0x1234...")
_QUOTED_PAIR_RE = re.compile(
    r"""['"]\s*([A-Za-z_][A-Za-z_0-9]*)\s*=\s*['"]\s*[,:]\s*['"]\s*(""" + _NUM + r""")\s*['"]""")
# 形如 n = '0x1234' / n = "12345"
_QUOTED_ASSIGN_RE = re.compile(
    r"""\b([A-Za-z_][A-Za-z_0-9]*)\s*=\s*['"](""" + _NUM + r""")['"]""")


def _to_int(s: str) -> Optional[int]:
    s = s.strip().replace("_", "")
    # Python 2 的长整型后缀 0x123L / 123L
    if len(s) > 1 and s[-1] in ("l", "L"):
        s = s[:-1]
    if not s:
        return None
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        return None


def _norm_name(name: str) -> Tuple[str, Optional[int]]:
    """返回 (标准名, 序号)。n1 -> ('n', 1)"""
    low = name.lower()
    m = re.fullmatch(r"([a-z_]+?)(\d+)", low)
    idx = None
    base = low
    if m:
        base, idx = m.group(1), int(m.group(2))
        low = base
    if low in _NAME_MAP:
        return _NAME_MAP[low], idx
    # 前缀匹配：如 p_low / q_high / n_big
    for key in ("dp", "dq", "phi", "p", "q", "n", "e", "c", "d", "hint", "leak"):
        if low.startswith(key) and len(low) <= len(key) + 8:
            return _NAME_MAP[key], idx
    return name, idx


@dataclass
class RSAContext:
    n: Optional[int] = None
    e: Optional[int] = None
    c: Optional[int] = None
    p: Optional[int] = None
    q: Optional[int] = None
    d: Optional[int] = None
    dp: Optional[int] = None
    dq: Optional[int] = None
    phi: Optional[int] = None
    m_hint: Optional[int] = None

    # 多组参数
    ns: List[int] = field(default_factory=list)
    es: List[int] = field(default_factory=list)
    cs: List[int] = field(default_factory=list)
    triples: List[Tuple[int, int, int]] = field(default_factory=list)

    hints: Dict[str, int] = field(default_factory=dict)
    leak_shift: Optional[int] = None      # 形如 hint = p >> 300
    leak_low_bits: Optional[int] = None   # 形如 hint = p & ((1<<200)-1)
    raw: str = ""
    notes: List[str] = field(default_factory=list)

    # ---- 工具方法 ----
    def has(self, *names: str) -> bool:
        return all(getattr(self, nm, None) is not None for nm in names)

    def summary(self) -> str:
        lines = []
        for nm in ("n", "e", "c", "p", "q", "d", "dp", "dq", "phi"):
            v = getattr(self, nm)
            if v is None:
                continue
            s = str(v)
            if len(s) > 40:
                s = s[:16] + f"...({v.bit_length()}bit)"
            lines.append(f"  {nm:4s} = {s}")
        if len(self.ns) > 1:
            lines.append(f"  ns   = {len(self.ns)} 个模数")
        if len(self.es) > 1:
            lines.append(f"  es   = {self.es}")
        if len(self.cs) > 1:
            lines.append(f"  cs   = {len(self.cs)} 个密文")
        for k, v in self.hints.items():
            lines.append(f"  hint[{k}] = {v if v.bit_length() < 128 else str(v)[:24] + '...'}")
        if self.leak_shift:
            lines.append(f"  线索: 高位泄露 (>>{self.leak_shift})")
        if self.leak_low_bits:
            lines.append(f"  线索: 低位泄露 (&{self.leak_low_bits})")
        for nt in self.notes:
            lines.append(f"  注: {nt}")
        return "\n".join(lines) if lines else "  (空)"

    def extend_from(self, other: "RSAContext") -> None:
        for nm in ("n", "e", "c", "p", "q", "d", "dp", "dq", "phi", "m_hint"):
            if getattr(self, nm) is None and getattr(other, nm) is not None:
                setattr(self, nm, getattr(other, nm))


def parse_text(text: str) -> RSAContext:
    """从题面文本里抽参数。"""
    ctx = RSAContext(raw=text)
    t = text

    # 列表形式：ns = [..], cs = [..]
    list_vals: Dict[str, List[int]] = {}
    for m in _LIST_RE.finditer(t):
        name = m.group(1).lower()
        items = re.findall(_NUM, m.group(2))
        vals = [v for v in (_to_int(x) for x in items) if v is not None]
        if vals:
            list_vals[name] = vals
    # 列表内容不要被后续单值解析污染
    t_no_list = _LIST_RE.sub(" ", t)

    singles: Dict[str, List[int]] = {}
    for m in _ASSIGN_RE.finditer(t_no_list):
        val = _to_int(m.group(2))
        if val is None:
            continue
        nm, idx = _norm_name(m.group(1))
        singles.setdefault(nm, []).append(val)

    # 引号包裹的键值对：('n=', '0x1234...') / n = '0x1234'
    quoted: Dict[str, List[int]] = {}
    for m in _QUOTED_PAIR_RE.finditer(t):
        nm, _i = _norm_name(m.group(1))
        val = _to_int(m.group(2))
        if val is not None:
            quoted.setdefault(nm, []).append(val)
    for m in _QUOTED_ASSIGN_RE.finditer(t):
        nm, _i = _norm_name(m.group(1))
        val = _to_int(m.group(2))
        if val is not None:
            quoted.setdefault(nm, []).append(val)

    # 单值直接落位（普通赋值优先，引号形式补缺）
    for nm in ("n", "e", "c", "p", "q", "d", "dp", "dq", "phi"):
        vals = [v for v in (singles.get(nm) or quoted.get(nm) or []) if v > 0]
        if vals:
            setattr(ctx, nm, vals[0])

    # 多值：n1..nk / c1..ck / e1..ek
    if len(singles.get("n", [])) > 1:
        ctx.ns = singles["n"]
        ctx.n = ctx.ns[0]
    if len(singles.get("c", [])) > 1:
        ctx.cs = singles["c"]
        ctx.c = ctx.cs[0]
    es_vals = [v for v in singles.get("e", []) if v > 0]
    if len(es_vals) > 1:
        ctx.es = es_vals
    for key, target in (("ns", "ns"), ("cs", "cs"), ("es", "es"), ("n_list", "ns"),
                        ("c_list", "cs"), ("narray", "ns")):
        if key in list_vals and not getattr(ctx, target):
            setattr(ctx, target, list_vals[key])
    if list_vals.get("ns"):
        ctx.ns = list_vals["ns"]
        ctx.n = ctx.ns[0]
    if list_vals.get("cs"):
        ctx.cs = list_vals["cs"]
        ctx.c = ctx.cs[0]
    if list_vals.get("es"):
        ctx.es = list_vals["es"]

    # 组装三元的 (n, e, c)，用于广播 / 共模
    if ctx.ns and ctx.cs and len(ctx.ns) == len(ctx.cs):
        es = ctx.es if len(ctx.es) == len(ctx.ns) else [ctx.e or 3] * len(ctx.ns)
        ctx.triples = list(zip(ctx.ns, es, ctx.cs))

    # p/q 若不整除 n，说明是残缺值（如高位泄露 p>>60<<60），不能当因子，
    # 转为 hint 交给 Coppersmith
    if ctx.n:
        for nm in ("p", "q"):
            v = getattr(ctx, nm)
            if v and v > 1 and ctx.n % v != 0:
                ctx.hints.setdefault("hint", v)
                ctx.notes.append(f"{nm} 不整除 n，按泄露值处理")
                setattr(ctx, nm, None)

    # 线索值
    for nm in ("hint", "leak"):
        if singles.get(nm):
            ctx.hints[nm] = singles[nm][0]
        elif quoted.get(nm):
            ctx.hints[nm] = quoted[nm][0]
    for nm in ("x", "y", "m"):
        if singles.get(nm):
            ctx.hints[nm] = singles[nm][0]

    # >> 位移线索
    for m in _SHIFT_RE.finditer(t):
        ctx.leak_shift = int(m.group(2))
        ctx.notes.append(f"检测到位运算 {m.group(1)} >> {m.group(2)}")
        break
    # 低位掩码线索
    if re.search(r"&\s*\(?\s*\(\s*1\s*<<\s*(\d+)\s*\)\s*-\s*1", t):
        mm = re.search(r"&\s*\(?\s*\(\s*1\s*<<\s*(\d+)\s*\)\s*-\s*1", t)
        ctx.leak_low_bits = int(mm.group(1))
    for mm in re.finditer(r"(?:1\s*<<\s*(\d+))|(?:2\s*\*\*\s*(\d+))|(?:2\^(\d+))", t):
        v = next(g for g in mm.groups() if g)
        if not ctx.leak_shift and int(v) > 32:
            ctx.notes.append(f"出现移位量 2^{v}")

    # 常见线索词
    low = t.lower()
    if "dp" in low and "dq" in low:
        ctx.notes.append("题面出现 dp 与 dq")
    if re.search(r"\bp\s*>\s*q\b|p\s*-\s*q", low):
        ctx.notes.append("题目暗示 p、q 接近")

    # 兜底：密文常以裸数字形式贴在注释里（如 "#12045854..."），没有 c= 前缀
    known = {v for v in (ctx.n, ctx.e, ctx.c, ctx.p, ctx.q, ctx.d) if v}
    loose = []
    for m in re.finditer(_NUM, t):
        v = _to_int(m.group(0))
        if v is None or v in known or v < (1 << 128):
            continue
        if v not in loose:
            loose.append(v)
    # 上万位的孤立大数：几乎只可能是 MT19937 的 getrandbits 输出
    huge = [v for v in loose if v.bit_length() > 10000]
    if huge and "mt_output" not in ctx.hints:
        ctx.hints["mt_output"] = max(huge, key=lambda x: x.bit_length())
        ctx.notes.append("检测到超长随机数（疑似 MT19937 输出）")
        loose = [v for v in loose if v.bit_length() <= 10000]
    if ctx.c is None and len(loose) == 1:
        ctx.c = loose[0]
        ctx.notes.append("从题面的孤立大整数推断 c")

    # 从题目脚本里提取关键参数（脚本 + output.txt 一起喂入时特别有用）
    m = re.search(r"getPrime\s*\(\s*(\d+)\s*[,)]", t)
    if m:
        ctx.hints["prime_bits"] = int(m.group(1))
        ctx.notes.append(f"脚本里 getPrime({m.group(1)})")
    else:
        m = re.search(r"keysize\s*=\s*(\d+)", t)
        if m:
            ctx.hints["prime_bits"] = int(m.group(1))
            ctx.notes.append(f"脚本里 keysize={m.group(1)}")
    m = re.search(r"getrandbits\s*\(\s*(\d{4,})\s*\)", t)
    if m:
        k = int(m.group(1))
        if k >= 19968:
            ctx.hints["mt_bits"] = k
            ctx.notes.append(f"脚本里 getrandbits({k})，够恢复 MT19937")
    return ctx


def parse_json(text: str) -> RSAContext:
    """支持 {"n":..,"e":..,"c":..} 或 {"ns":[..],"cs":[..]} 形式。"""
    data = json.loads(text)
    ctx = RSAContext(raw=text)
    for k, v in data.items():
        nm, _ = _norm_name(k)
        if isinstance(v, list):
            vals = [int(x) if not isinstance(x, str) else (_to_int(x) or 0) for x in v]
            if nm == "n":
                ctx.ns = vals
            elif nm == "c":
                ctx.cs = vals
            elif nm == "e":
                ctx.es = vals
            elif nm in ("n", "c", "e"):
                setattr(ctx, nm, vals[0])
            else:
                ctx.hints[nm] = vals
        else:
            try:
                val = int(v) if not isinstance(v, str) else (_to_int(v) if _to_int(v) is not None else v)
            except (TypeError, ValueError):
                val = v
            if isinstance(val, int):
                if nm in ("n", "e", "c", "p", "q", "d", "dp", "dq", "phi"):
                    setattr(ctx, nm, val)
                else:
                    ctx.hints[nm] = val
    if ctx.ns and ctx.cs and len(ctx.ns) == len(ctx.cs):
        es = ctx.es if len(ctx.es) == len(ctx.ns) else [ctx.e or 3] * len(ctx.ns)
        ctx.triples = list(zip(ctx.ns, es, ctx.cs))
    return ctx


def parse_any(text: str) -> RSAContext:
    s = text.strip()
    if s.startswith("{") or s.startswith("["):
        try:
            return parse_json(s)
        except Exception:
            pass
    return parse_text(s)


def from_pubkey_file(path: str) -> RSAContext:
    """从 PEM/DER 公钥（或私钥）读 n、e。"""
    from Crypto.PublicKey import RSA

    with open(path, "rb") as f:
        key = RSA.import_key(f.read())
    return RSAContext(n=key.n, e=key.e)
