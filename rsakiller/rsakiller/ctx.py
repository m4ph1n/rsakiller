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
    "p": "p", "pp": "p", "prime1": "p", "real_p": "p", "realp": "p",
    "q": "q", "qq": "q", "prime2": "q", "real_q": "q", "realq": "q",
    "d": "d", "dd": "d", "priv": "d", "privkey": "d", "private": "d",
    "dp": "dp", "dq": "dq", "d_p": "dp", "d_q": "dq", "dmp1": "dp", "dmq1": "dq",
    "qinv": "qinv", "qi": "qinv", "q_inv": "qinv", "iqmp": "qinv",
    "pinv": "pinv", "p_inv": "pinv", "ipmq": "pinv",
    "phi": "phi", "phin": "phi", "phip": "phi", "varphi": "phi", "fn": "phi",
    "hint": "hint", "leak": "leak", "high": "hint", "p_high": "hint",
    "ph": "hint", "leak_p": "hint", "hp": "hint", "pbar": "hint",
    "near_p": "near_p", "nearp": "near_p", "p_approx": "near_p", "pbar_near": "near_p",
    "sig": "sig", "signature": "sig", "fault_sig": "sig", "faulty_sig": "sig",
    "good_sig": "good_sig", "correct_sig": "good_sig",
    "msig": "signed_msg", "signed_msg": "signed_msg", "m_signed": "signed_msg",
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
    # 位宽/长度词：绝不与 n / p / q 混淆（nbit=256 不是 n）
    if low in ("nbit", "nbits", "bits", "bitlen", "keybits", "keysize", "bitsize",
               "n_bits", "bit", "pbits", "qbits", "length", "nb", "keylength",
               "n_bit", "bitss", "nlen", "key_len"):
        return "bits", idx
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
    qinv: Optional[int] = None
    phi: Optional[int] = None
    m_hint: Optional[int] = None

    # 部分信息泄露：near_p 是 p 的近似值（可以差一点点），d_low 是 d 的低位
    near_p: Optional[int] = None
    d_low: Optional[int] = None
    d_low_bits: Optional[int] = None

    # RSA-CRT 故障签名：sig 是错的那条，good_sig / signed_msg 用来核对
    sig: Optional[int] = None
    good_sig: Optional[int] = None
    signed_msg: Optional[int] = None

    # 多组参数
    ns: List[int] = field(default_factory=list)
    es: List[int] = field(default_factory=list)
    cs: List[int] = field(default_factory=list)
    triples: List[Tuple[int, int, int]] = field(default_factory=list)

    # 泄露的 (p-a)(q-b) 值：list of (a, b, val)，形如 "(p-2)*(q-1)=<val>"
    phi_pairs: List[Tuple[int, int, int]] = field(default_factory=list)

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
        for nm in ("n", "e", "c", "p", "q", "d", "dp", "dq", "qinv", "phi"):
            v = getattr(self, nm)
            if v is None:
                continue
            s = str(v)
            if len(s) > 40:
                s = s[:16] + f"...({v.bit_length()}bit)"
            lines.append(f"  {nm:4s} = {s}")
        if self.near_p:
            s = str(self.near_p)
            if len(s) > 40:
                s = s[:16] + f"...({self.near_p.bit_length()}bit)"
            lines.append(f"  near_p = {s}（p 的近似值）")
        if self.d_low is not None:
            bits = self.d_low_bits or self.d_low.bit_length()
            lines.append(f"  d_low = {self.d_low if self.d_low.bit_length() < 128 else str(self.d_low)[:24] + '...'}"
                         f"（d 的低 {bits} bit）")
        if self.sig is not None:
            lines.append(f"  sig  = {str(self.sig)[:24]}...（RSA-CRT 故障签名）")
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
        for nm in ("n", "e", "c", "p", "q", "d", "dp", "dq", "qinv", "phi", "m_hint",
                   "near_p", "d_low", "d_low_bits", "sig", "good_sig", "signed_msg"):
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
    for nm in ("n", "e", "c", "p", "q", "d", "dp", "dq", "qinv", "phi",
               "near_p", "sig", "good_sig", "signed_msg"):
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
    # a / b：常见于题面给出多项式/线性关系（如 b = q - p*a），存作 hint，
    # 由对应攻击（二次方程分解、Coppersmith）去消费。只收较大的值以免误抓。
    for nm in ("a", "b"):
        vals = [v for v in (singles.get(nm) or []) if v > (1 << 100)]
        if vals:
            ctx.hints[nm] = vals[0]

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

    # 部分私钥泄露：脚本里常见的 d & ((1<<k)-1)、d % 2**k、d_low
    m = re.search(r"\bd\s*%\s*(?:2\s*\*\*\s*(\d+)|\(\s*1\s*<<\s*(\d+)\s*\))", t)
    if m and ctx.d is None:
        shot = next(g for g in m.groups() if g)
        # d 的低 k 位是单独给的值：顺着找到它落的变量名
        var = re.search(r"([A-Za-z_][A-Za-z_0-9]*)\s*=\s*[^=\n]*\bd\s*%\s*"
                        r"(?:2\s*\*\*\s*\d+|\(\s*1\s*<<\s*\d+\s*\))", t)
        if var:
            nm, _ = _norm_name(var.group(1))
            val = (singles.get(nm) or quoted.get(nm) or [None])[0]
            if val:
                ctx.d_low, ctx.d_low_bits = val, int(shot)
                ctx.notes.append(f"检测到 d 的低 {shot} bit 泄露")

    # RSA-CRT 故障签名：题面里同时出现「正确的消息」和「错掉的签名」
    if ctx.sig is not None and ctx.signed_msg is None and ctx.c is not None:
        ctx.signed_msg = ctx.c
        ctx.notes.append("把 c 当作被签名的消息用于 Bellcore 校验")

    # 兜底：密文常以裸数字形式贴在注释里（如 "#12045854..."），没有 c= 前缀
    known = {v for v in (ctx.n, ctx.e, ctx.c, ctx.p, ctx.q, ctx.d, ctx.sig,
                         ctx.good_sig, ctx.signed_msg, ctx.near_p) if v}
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

    # (p-a)*(q-b) 型泄露：形如 #(p-2)*(q-1) = <val>（phi 的线性变形）
    for pm in re.finditer(
        r"\(\s*p\s*([+-])\s*(\d+)\s*\)\s*\*\s*\(\s*q\s*([+-])\s*(\d+)\s*\)\s*=\s*(" + _NUM + r")",
        t, re.I):
        s1, n1, s2, n2 = pm.group(1), int(pm.group(2)), pm.group(3), int(pm.group(4))
        a = n1 if s1 == '-' else -n1   # (p-2) => a=2
        b = n2 if s2 == '-' else -n2   # (q-1) => b=1
        val = _to_int(pm.group(5))
        if val is None:
            continue
        ctx.phi_pairs.append((a, b, val))
    if ctx.phi_pairs:
        ctx.notes.append(f"检测到 {len(ctx.phi_pairs)} 组 (p-a)(q-b) 泄露值")
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
                if nm in ("n", "e", "c", "p", "q", "d", "dp", "dq", "qinv", "phi",
                          "near_p", "sig", "good_sig", "signed_msg"):
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
    """从 PEM/DER 公钥（或私钥）读 n、e；私钥文件连带读出 p、q、d 等。"""
    from Crypto.PublicKey import RSA

    with open(path, "rb") as f:
        key = RSA.import_key(f.read())
    ctx = RSAContext(n=key.n, e=key.e)
    if key.has_private():
        ctx.d = key.d
        ctx.p = key.p
        ctx.q = key.q
        if key.u:
            ctx.qinv = key.u      # pycryptodome 的 u = q^-1 mod p
        ctx.notes.append("从私钥文件读取到完整私钥")
    return ctx
