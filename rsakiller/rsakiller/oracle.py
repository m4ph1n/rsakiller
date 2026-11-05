"""交互式 oracle 类攻击（LSB / parity / Bleichenbacher 骨架）。

这类题必须和远程服务交互，无法全自动——这里给出可直接套用的实现。
"""
from __future__ import annotations

from typing import Callable, List, Optional

from . import utils as U


def lsb_oracle_attack(n: int, e: int, c: int, oracle: Callable[[int], int],
                      rounds: Optional[int] = None) -> int:
    """最小有效位预言机。

    oracle(cipher) -> 0/1，返回解密结果的奇偶性。
    """
    k = rounds or n.bit_length()
    lower, upper = 0, n
    c2 = c % n
    two_e = U.powmod(2, e, n)
    for _ in range(k):
        c2 = (c2 * two_e) % n
        bit = int(oracle(c2))
        mid = (lower + upper) // 2
        if bit == 1:
            lower = mid
        else:
            upper = mid
    return upper


def parity_oracle_attack(n: int, e: int, c: int, oracle: Callable[[int], int]) -> int:
    """m > n/2 返回 1 的预言机，本质与 LSB 等价。"""
    k = n.bit_length()
    lower, upper = 0, n
    c2 = c % n
    half_e = U.powmod(U.inv(2, n) or 0, e, n)
    for _ in range(k):
        # 判断解密结果是否落在上半区间
        bit = int(oracle(c2))
        mid = (lower + upper) // 2
        if bit == 1:
            lower = mid
        else:
            upper = mid
        c2 = (c2 * half_e) % n
    return upper


def bleichenbacher_skeleton(n: int, e: int, c: int, oracle: Callable[[int], bool]):
    """PKCS#1 v1.5 padding oracle 骨架（返回是否为合法填充）。

    完整实现在 rsakiller2 里意义不大——CTF 里通常只需按题目微调区间条件。
    """
    B = 1 << (8 * (n.bit_length() // 8 - 2))
    # 第一轮：找到第一个合法区间
    c2 = c
    for _ in range(1 << 20):
        if oracle(c2):
            break
        c2 = (c2 * U.powmod(2, e, n)) % n
    return c2  # 交给调用方继续按标准流程收敛区间
