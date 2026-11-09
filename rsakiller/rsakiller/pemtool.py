"""加密 PEM（OpenSSL 传统格式，DES-EDE3-CBC）恢复工具。

对齐 pycryptodome Crypto/IO/PEM.decode 的派钥方式：
    key||iv 侧：key = _EVP_BytesToKey(passphrase, salt=DEK-Info IV(8B), 24)
    CBC IV     = salt 本身（PEM.decode 里 DES3.new(key, MODE_CBC, salt)）

PEM body 是"一个" base64 blob 按 64 字符/行切分（48 字节 = 6 个 DES 块/行）；
CBC 链跨整个 blob 连续。行被 '*'*64 破坏时，每个受影响行的第 1 块解不出
（其 XOR 前驱密文块丢失），其余块仍可靠 —— 据此把明文划分成可靠区间，
再按 DER 总长定位各 INTEGER，从可靠尾部切出完整 qInv（22_ezrsa_CISCN：
1024-bit pycryptodome 导出，qInv TLV 在偏移 542，值 544..608/609）。
"""
from __future__ import annotations

import base64
from typing import List, Optional, Tuple

from Crypto.Cipher import DES3
from Crypto.IO.PEM import _EVP_BytesToKey

_HEAD_HEADER_LINES = 3   # BEGIN 行、Proc-Type、DEK-Info


def _parse_pem(pem_text: str):
    """返回 (body_lines, salt, key_len)。body 行按文件顺序、不排序不去重；
    salt 即 DEK-Info 十六进制 IV，同时充当 KDF salt 与 CBC IV。"""
    lines = pem_text.replace(" ", "").splitlines()
    body: List[bytes] = []
    salt = None
    key_len = 24
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("-----"):
            continue
        if s.startswith("Proc-Type:"):
            continue
        if s.startswith("DEK-Info:"):
            algo, _, ivhex = s[len("DEK-Info:"):].partition(",")
            algo = algo.strip()
            salt = bytes.fromhex(ivhex.strip())
            key_len = {"DES-EDE3-CBC": 24, "DES-CBC": 8,
                       "AES-128-CBC": 16, "AES-192-CBC": 24,
                       "AES-256-CBC": 32}.get(algo, 24)
            continue
        body.append(s.encode())
    return body, salt, key_len


def _ciphertext_and_reliability(body: List[bytes], block: int = 8):
    """还原完整密文（缺失行用 b'A'*len 占位，保证块序）与逐块可靠标志。

    第 i 块明文 P_i = D(C_i) XOR C_{i-1} 可靠 iff C_i 与 C_{i-1} 都存在
    （C_{-1} = IV）。占位行仅用于维持块索引；占位块一律不可靠。"""
    ct_parts, present = [], []
    for ln in body:
        if set(ln) == {ord("*")}:
            ct_parts.append(b"A" * len(ln)); present.append(False)
        else:
            ct_parts.append(ln); present.append(True)
    ct = base64.b64decode(b"".join(ct_parts))
    nb = len(ct) // block
    reliable = []
    for i in range(nb):
        li = (i * block) // 48            # 每行 64 字符 base64 = 48 字节
        ok = present[li]
        if i > 0 and (i * block) % 48 == 0:
            ok = ok and present[li - 1]   # 行首块依赖上一行末块
        reliable.append(ok)
    return ct, reliable


def _ranges(flags: List[bool]) -> List[Tuple[int, int]]:
    """True 段 -> [(起始块, 结束块), ...]（半开区间）。"""
    out, s = [], None
    for i, f in enumerate(flags):
        if f and s is None:
            s = i
        if not f and s is not None:
            out.append((s, i)); s = None
    if s is not None:
        out.append((s, len(flags)))
    return out


def _derive(pw: bytes, salt: bytes, key_len: int) -> bytes:
    return _EVP_BytesToKey(pw, salt, key_len)


def _decrypt_head(ct: bytes, key: bytes, salt: bytes, nbytes: int) -> bytes:
    """解密前 nbytes 字节（必须落在第一可靠区间内）。"""
    c = DES3.new(key, DES3.MODE_CBC, salt)
    return c.decrypt(ct[:((nbytes + 7) // 8) * 8])[:nbytes]


def brute_passphrase(pem_text: str, digits: int = 6, subrange=None,
                     progress_every: int = 10**5):
    """对 OpenSSL 风格加密 PEM（DES-EDE3-CBC）做数字口令爆破。

    判定信号：解密头部以 0x30 0x82 开头（DER SEQUENCE，长形式长度 >0x80）。
    subrange=(lo, hi) 只测 [lo, hi) 切片。返回 (passphrase_int, key24, iv8)
    或 None；iv8 即 salt（DEK-Info IV）。
    """
    body, salt, key_len = _parse_pem(pem_text)
    if salt is None:
        raise ValueError("PEM 未加密（无 DEK-Info），无需爆破")
    # 取首个连续完好 run 的前 144 字节（足够覆盖 30 82 02 01 00 + n 头），
    # 完好 run 长度不足 144 字节时退而用全部前导完好字节。
    runs = _ranges(_block_flags(body))
    head_len = min(144, (runs[0][1] - runs[0][0]) * 8) if runs else 144
    head_ct = ct_bytes(body)[:head_len]
    lo = 0 if subrange is None else int(subrange[0])
    hi = 10 ** digits if subrange is None else int(subrange[1])
    fmt = "%0" + str(digits) + "d"
    for i in range(lo, hi):
        pw = (fmt % i).encode()
        key = _derive(pw, salt, key_len)
        pt = DES3.new(key, DES3.MODE_CBC, salt).decrypt(head_ct)
        if pt[0] == 0x30 and pt[1] == 0x82:
            return int(i), key, salt
        if progress_every and (i - lo + 1) % progress_every == 0:
            print(f"  [brute] {i + 1} tested", flush=True)
    return None


# --- 内部小工具：brute_passphrase 需要 ct/reliable 标志，单独封装避免重复解密 ---

def _block_flags(body: List[bytes]):
    return _ciphertext_and_reliability(body)[1]


def ct_bytes(body: List[bytes]) -> bytes:
    return _ciphertext_and_reliability(body)[0]


def _tlv(buf: bytes, off: int):
    """DER TLV 头解析，返回 (tag, length, header_len)。"""
    tag = buf[off]
    l = buf[off + 1]
    h = 2
    if l & 0x80:
        nb = l & 0x7F
        l = int.from_bytes(buf[off + 2:off + 2 + nb], "big")
        h = 2 + nb
    return tag, l, h


def _parse_head(pt_head: bytes) -> Tuple[int, int]:
    """解析 DER 前缀，返回 (n, e)。要求头部字节完整可靠。"""
    tag, L, h = _tlv(pt_head, 0)
    assert tag == 0x30, hex(tag)
    o = h
    vals = {}
    for name in ("version", "n", "e"):
        t, l, hh = _tlv(pt_head, o)
        assert t == 0x02, hex(t)
        vals[name] = int.from_bytes(pt_head[o + hh:o + hh + l], "big")
        o += hh + l
    return vals["n"], vals["e"]


def recover_pub(pem_text: str, passphrase_int: int) -> Tuple[int, int]:
    """解密完好头部行，解析 DER 前缀，返回 (n, e)。"""
    body, salt, key_len = _parse_pem(pem_text)
    key = _derive(b"%d" % int(passphrase_int), salt, key_len)
    runs = _ranges(_block_flags(body))
    head_len = min(144, (runs[0][1] - runs[0][0]) * 8)
    pt_head = _decrypt_head(ct_bytes(body), key, salt, head_len)
    return _parse_head(pt_head)


def recover_qinv(pem_text: str, passphrase_int: int) -> int:
    """从完好尾部行恢复完整 qInv（PKCS#1 RSAPrivateKey 最后一个 INTEGER）。

    破坏-CBC 细节：缺失行之后的首个明文块是垃圾；先用 PKCS#7 padding 从
    尾块推 DER 总长，再按 PKCS#1 顶层布局（version/n/e 头 + 9 个 INTEGER）
    定位 qInv TLV，仅从可靠区间内切值。1024-bit pycryptodome 导出时 qInv
    TLV 起于 542（值 544..608/609），已对真实数据验证。"""
    body, salt, key_len = _parse_pem(pem_text)
    key = _derive(b"%d" % int(passphrase_int), salt, key_len)
    ct, reliable = _ciphertext_and_reliability(body)
    nb = len(ct) // 8
    # 手动 CBC 解全部块（占位块结果无意义，可靠标志已排除它们）
    ecb = DES3.new(key, DES3.MODE_ECB)
    pt = bytearray(len(ct))
    prev = salt
    for i in range(nb):
        c = ct[i * 8:(i + 1) * 8]
        blk = bytes(a ^ b for a, b in zip(ecb.decrypt(c), prev))
        pt[i * 8:(i + 1) * 8] = blk
        prev = c
    pad = pt[-1]
    der_len = len(pt) - pad
    assert 0 < pad <= 8, f"异常 padding {pad}"
    # 可靠字节区间（块 -> 字节）
    byte_rel = bytearray(nb)
    for i in range(nb):
        byte_rel[i] = 1 if reliable[i] else 0

    def is_reliable(off: int) -> bool:
        return byte_rel[off // 8] == 1

    # qInv 是最后一个 INTEGER：其 TLV 结束 == der_len。
    # 头部布局固定：seq hdr(4) + version(3) + n(3+129) + e(2+3) = 144 字节
    # （1024-bit n 需 0x81 81 前导）。剩余 d..qInv 共 6 个 INTEGER。
    # 从最后一个可靠 run 的起点前 4 字节扫到 der_len：枚举 qInv 的 TLV 头
    # 起点，使 qInv.value_end == der_len 且值字节全部可靠。
    # 1024-bit p/q/dP/dQ/qInv 的值长 64 或 65（高位置 0 时多一个前导 0x00）。
    tail_run_start = _ranges(reliable)[-1][0] * 8
    for qoff in range(max(4, tail_run_start - 4), der_len):
        if not is_reliable(qoff):
            continue
        if pt[qoff] != 0x02:
            continue
        try:
            _, ql, qh = _tlv(pt, qoff)
        except IndexError:
            continue
        qend = qoff + qh + ql
        if qend != der_len or ql not in (64, 65):
            continue
        if not all(is_reliable(x) for x in range(qoff, qend)):
            continue
        return int.from_bytes(pt[qoff + qh:qend], "big")
    raise ValueError("未能从可靠尾部定位 qInv（布局与假设不符）")
