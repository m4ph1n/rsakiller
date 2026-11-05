"""MT19937 状态恢复 + RSA 素数重放。

典型题型：脚本先打印一个大随机数，再用它之后的小种子重新播种生成 RSA 素数。

    print(random.getrandbits(20000))
    random.seed(random.getrandbits(32))
    r = lambda x: bytes([random.getrandbits(8)])
    P = getPrime(1024, randfunc=r)
    Q = getPrime(1024, randfunc=r)

19968 bit 以上就够恢复 MT19937 的 624 个 32-bit 状态。恢复后可预测
下一个 32-bit 输出（即新种子），再重放素数生成过程。

难点在于 getPrime 的语义随 PyCryptodome 版本不同：
  * 新版（4.x）：每轮 getRandomNBitInteger 重新生成候选
  * 旧版（3.x）：生成一次后 number += 2 递增搜索
且 isPrime 内部的 Miller-Rabin 也会消耗 randfunc。因此这里对
"语义 × 跳过字节数"做有限枚举，用"解密结果是否可读"来判定。
"""
from __future__ import annotations

import random
from typing import List, Optional, Tuple

MASK = 0xFFFFFFFF
_BASE_E = (65537, 3, 17, 257, 65539)


def _unshift_right(y: int, shift: int) -> int:
    x = y
    for _ in range(32 // shift + 1):
        x = y ^ (x >> shift)
    return x & MASK


def _unshift_left(y: int, shift: int, mask: int) -> int:
    x = y
    for _ in range(32 // shift + 1):
        x = y ^ ((x << shift) & mask)
    return x & MASK


def untemper(y: int) -> int:
    y = _unshift_right(y, 18)
    y = _unshift_left(y, 15, 0xEFC60000)
    y = _unshift_left(y, 7, 0x9D2C5680)
    y = _unshift_right(y, 11)
    return y


def recover(big: int) -> Optional[random.Random]:
    """从 getrandbits 的大整数输出恢复 MT 状态，返回已对齐的 Random。"""
    bits = big.bit_length()
    nwords = (bits + 31) // 32
    if nwords < 624:
        return None
    words = [(big >> (32 * i)) & MASK for i in range(nwords)]
    state = [untemper(w) for w in words[:624]]
    rng = random.Random()
    rng.setstate((3, tuple(state + [624]), None))
    if nwords > 624 and rng.getrandbits(32) != words[624]:
        return None            # 校验失败
    return rng


def predict_seed(big: int) -> Optional[int]:
    """预测 random.seed(...) 用的那个 32-bit 种子。"""
    rng = recover(big)
    if rng is None:
        return None
    return rng.getrandbits(32)


def _delta_15(r) -> int:
    """新版 getRandomInteger(1023)：randfunc(127) 1 字节 + randfunc(1) 高 7 位。"""
    b1 = r.getrandbits(8)
    b2 = r.getrandbits(8) >> 1
    return (b2 << 8) | b1


def _delta_8(r) -> int:
    """旧接口 getRandomInteger(1024)：randfunc(128) 1 字节。"""
    return r.getrandbits(8)


def _gen_new(r, base: int, delta_fn, is_prime, max_try: int = 800) -> Optional[int]:
    """新版语义：每轮重新生成候选。"""
    for _ in range(max_try):
        cand = base | ((delta_fn(r)) | 1)
        if is_prime(cand):
            return cand
    return None


def _gen_inc(r, base: int, delta_fn, is_prime, max_try: int = 6000) -> Optional[int]:
    """旧版语义：生成一次后 +2 递增。"""
    cand = base | ((delta_fn(r)) | 1)
    for _ in range(max_try):
        if is_prime(cand):
            return cand
        cand += 2
    return None


def _looks_text(b: bytes) -> bool:
    if not b or len(b) < 4:
        return False
    ok = sum(32 <= x < 127 or x in (9, 10, 13) for x in b)
    return ok / len(b) > 0.85


def attack(big: int, c: int, pbits: Optional[int] = None,
           max_skip: int = 25, verbose: bool = False) -> Optional[Tuple[bytes, int, int]]:
    """尝试恢复并重放，返回 (明文, 语义, 跳过字节数) 或 None。"""
    from Crypto.Util.number import isPrime, long_to_bytes

    rng = recover(big)
    if rng is None:
        return None
    seed = rng.getrandbits(32)
    if verbose:
        print(f"    [MT] 状态恢复成功，预测种子 {seed}")

    if pbits is None:
        # c < N 且 N 约为 2*pbits-1 或 2*pbits 位；从 c 的位宽只能估个大概，
        # 必须 ±1 试（差一位 base 就全错）
        est = (c.bit_length() + 1) // 2
        pbits_list: List[int] = [est + 1, est, est + 2]
    else:
        pbits_list = [pbits]

    for pb in pbits_list:
        base = 1 << (pb - 1)
        got = _attack_one(seed, base, c, max_skip, verbose)
        if got:
            return got
    return None


def _attack_one(seed: int, base: int, c: int, max_skip: int,
                verbose: bool):
    from Crypto.Util.number import isPrime, long_to_bytes

    E = 65537

    for delta_fn, tag in ((_delta_15, "15bit"), (_delta_8, "8bit")):
        for kind, gen in (("inc", _gen_inc), ("new", _gen_new)):
            # P 只生成一次，缓存其后的 MT 状态，避免每个 skip 分支重复搜索
            r1 = random.Random(seed)
            P = gen(r1, base, delta_fn, isPrime)
            if not P:
                continue
            state_after_p = r1.getstate()
            if verbose:
                print(f"    [MT] P 就绪（{kind}/{tag}, base=2^{base.bit_length()-1}, "
                      f"offset={P - base}）")

            for skip in range(0, max_skip + 1):
                r2 = random.Random()
                r2.setstate(state_after_p)
                for _ in range(skip):
                    r2.getrandbits(8)
                Q = gen(r2, base, delta_fn, isPrime)
                if not Q:
                    continue
                N = P * Q
                if c >= N:
                    continue
                phi = (P - 1) * (Q - 1)
                if phi % E == 0:
                    continue
                try:
                    d = pow(E, -1, phi)
                    m = pow(c, d, N)
                except Exception:
                    continue
                b = long_to_bytes(m)
                if _looks_text(b):
                    if verbose:
                        print(f"    [MT] 命中：语义={kind}/{tag} skip={skip} "
                              f"pbits={base.bit_length()}")
                    return b, 0 if kind == "new" else 1, skip
    return None
