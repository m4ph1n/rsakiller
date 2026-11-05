"""合成题目自测：为每一类攻击造一道题，验证工具能自动识别并解出。"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Util.number import getPrime, inverse

from rsakiller import utils as U
from rsakiller.ctx import RSAContext, parse_any
from rsakiller.solver import Options, solve

FLAG = b"flag{synthetic_test_2026}"
RESULTS = []


def check(name: str, ctx: RSAContext, expect, opts: Options = None, timeout=60):
    """expect 为 bytes 时比对文本，为 int 时比对明文整数。"""
    t0 = time.time()
    use_sage = "--no-sage" not in sys.argv
    if opts is None:
        opts = Options(online=False, use_sage=use_sage)
    else:
        opts.use_sage = use_sage
    res = solve(ctx, opts)
    dt = time.time() - t0
    ok = bool(res) and res.m is not None and \
        U.powmod(res.m, ctx.e, ctx.n) == (ctx.c or 0) % ctx.n
    if isinstance(expect, int):
        exact = bool(res) and res.m is not None and (res.m % ctx.n) == expect % ctx.n
    else:
        exact = bool(res) and res.text() == expect
    RESULTS.append((name, ok, exact, res.attack if res else None, dt))
    status = "PASS" if exact else ("校验过但内容不符" if ok else "FAIL")
    print(f"  {status:<12} {name:<22} {res.attack if res else '-':<22} {dt:6.2f}s"
          + ("" if exact else f"  got={res.text() if res else None}"))


def rand_int(bits: int) -> int:
    """生成指定位数的随机整数（最高位为 1）。"""
    import random

    v = random.getrandbits(bits) | (1 << (bits - 1)) | 1
    return v


def make_key(bits=512, e=65537):
    while True:
        p, q = getPrime(bits), getPrime(bits)
        n = p * q
        if U.gcd(e, (p - 1) * (q - 1)) == 1:
            return p, q, n


def m_of(flag: bytes) -> int:
    return U.bytes_to_long(flag)


# ---------------------------------------------------------------- 各类题目
def t_direct():
    p, q, n = make_key(512)
    e, c = 65537, 0
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("已知 p/q", RSAContext(n=n, e=e, c=c, p=p, q=q), FLAG)


def t_known_d():
    p, q, n = make_key(512)
    e = 65537
    d = inverse(e, (p - 1) * (q - 1))
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("已知私钥 d", RSAContext(n=n, e=e, c=c, d=d), FLAG)


def t_dp_leak():
    p, q, n = make_key(512)
    e = 65537
    dp = inverse(e, p - 1)
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("dp 泄露", RSAContext(n=n, e=e, c=c, dp=dp), FLAG)


def t_small_q():
    import gmpy2

    q = int(gmpy2.next_prime(700_000))   # 小于试除上限
    p = getPrime(512)
    n = p * q
    e = 65537
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("小素因子", RSAContext(n=n, e=e, c=c), FLAG)


def t_common_factor():
    p = getPrime(512)
    q1, q2 = getPrime(512), getPrime(512)
    n1, n2 = p * q1, p * q2
    e = 65537
    m = m_of(FLAG)
    c1, c2 = U.powmod(m, e, n1), U.powmod(m, e, n2)
    check("多模数共享因子", RSAContext(n=n1, e=e, c=c1, ns=[n1, n2], cs=[c1, c2]), FLAG)


def t_fermat():
    import gmpy2

    p = getPrime(512)
    q = int(gmpy2.next_prime(p + 5000))   # p、q 只差几千
    n = p * q
    e = 65537
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("p、q 接近(Fermat)", RSAContext(n=n, e=e, c=c), FLAG)


def t_wiener():
    p, q = getPrime(512), getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    while True:
        d = getPrime(120)          # 远小于 n^0.25
        if U.gcd(d, phi) == 1:
            break
    e = inverse(d, phi)
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("小私钥 d (Wiener)", RSAContext(n=n, e=e, c=c), FLAG)


def t_common_modulus():
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e1, e2 = 7, 11
    m = m_of(FLAG)
    c1, c2 = U.powmod(m, e1, n), U.powmod(m, e2, n)
    check("共模攻击", RSAContext(n=n, e=3, c=c1, es=[e1, e2], cs=[c1, c2]), FLAG)


def t_hastad():
    e = 3
    m = m_of(FLAG)                 # 约 200 bit，m^3 < 512*3 bit 的乘积
    triples, ns, cs = [], [], []
    for _ in range(3):
        p, q = getPrime(256), getPrime(256)
        n = p * q
        triples.append((n, e, U.powmod(m, e, n)))
        ns.append(n)
        cs.append(U.powmod(m, e, n))
    check("低指数广播(Hastad)", RSAContext(n=ns[0], e=e, c=cs[0], ns=ns, cs=cs, triples=triples), FLAG)


def t_small_e_root():
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e = 3
    m = m_of(FLAG)                 # m^3 < n，直接开方
    c = U.powmod(m, e, n)
    check("低指数小明文", RSAContext(n=n, e=e, c=c), FLAG)


def t_partial_p():
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e = 65537
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    ub = 150                       # p 约 512 bit，泄露 362 bit
    check("已知 p 高位", RSAContext(n=n, e=e, c=c, hints={"hint": p >> ub}), FLAG)


def t_m_high():
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e = 3
    # m 要足够大，保证 m^3 > n，否则会被"低指数小明文"抢先解掉
    m = (m_of(FLAG) << 200) | rand_int(200)
    assert m ** 3 > n
    ub = 40                        # 未知 40 bit
    mh = m >> ub
    c = U.powmod(m, e, n)
    check("已知明文高位", RSAContext(n=n, e=e, c=c, hints={"hint": mh}), m,
          Options(online=False, m_unknown_bits=ub))


def t_franklin_reiter():
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e = 3
    m1 = (m_of(FLAG) << 200) | rand_int(200)
    assert m1 ** 3 > n          # 保证不会被低指数开方抢先解掉
    m2 = m1 + 1
    c1, c2 = U.powmod(m1, e, n), U.powmod(m2, e, n)
    check("相关消息(FR)", RSAContext(n=n, e=e, c=c1, cs=[c1, c2]), m1)


def t_e_divides_phi():
    # 取 9 不整除 p-1 的实例：纯 Python 的 AMM 能直接开方，无需 Sage 兜底
    while True:
        p = getPrime(512)
        if (p - 1) % 3 == 0 and (p - 1) % 9 != 0:
            break
    q = getPrime(512)
    n = p * q
    e = 3
    # 明文要足够大，否则会被"低指数小明文"直接开方，测不到 AMM 分支
    m = (m_of(FLAG) << 200) | rand_int(200)
    assert m ** 3 > n
    c = U.powmod(m, e, n)
    check("e 与 phi 不互素", RSAContext(n=n, e=e, c=c, p=p, q=q), m)


def t_parser():
    p, q = getPrime(256), getPrime(256)
    n = p * q
    e = 65537
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    text = f"""题目描述：简单的 RSA，据说参数生成有漏洞。

n = {n}
e = {e}
c = {c}

hint: p 和 q 很接近
"""
    ctx = parse_any(text)
    ok = ctx.n == n and ctx.e == e and ctx.c == c
    RESULTS.append(("解析题面", ok, ok, "parser", 0.0))
    print(f"  {'PASS' if ok else 'FAIL':<10} {'题面解析':<22} {'-':<22} {0.0:6.2f}s")


def t_boneh_durfee_sage():
    """小私钥 d 但超出 Wiener 范围（d > n^0.25/3），只有 Boneh-Durfee 能解。"""
    import random
    from math import gcd as _gcd

    from rsakiller.attacks import wiener_attack

    random.seed(20261104)
    while True:
        p = getPrime(512)
        q = getPrime(512)
        n = p * q
        phi = (p - 1) * (q - 1)
        d = random.getrandbits(262) | (1 << 261) | 1
        if _gcd(d, phi) != 1:
            continue
        e = inverse(d, phi)
        if e > n // 2 and wiener_attack(n, e) is None:
            break
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("Boneh-Durfee(Sage)", RSAContext(n=n, e=e, c=c), FLAG,
          Options(online=False, sage_timeout=1200.0, bd_delta=0.26))


def t_partial_p_sage():
    """1024-bit n，只泄露 p 的 320 位高位（未知 192 位）——纯 Python 很慢。"""
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = 65537
    ub = 192
    hint = p >> ub
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("p 高位(大参数/Sage)", RSAContext(n=n, e=e, c=c, hints={"hint": hint}),
          FLAG, Options(online=False, sage_timeout=1200.0))


def main():
    print("=" * 72)
    print("  rsakiller 自测：为每类攻击合成一道题")
    print("=" * 72)
    tests = [
        ("解析题面", t_parser),
        ("已知 p/q", t_direct),
        ("已知私钥 d", t_known_d),
        ("dp 泄露", t_dp_leak),
        ("小素因子", t_small_q),
        ("多模数共享因子", t_common_factor),
        ("p、q 接近", t_fermat),
        ("小私钥 d", t_wiener),
        ("共模攻击", t_common_modulus),
        ("低指数广播", t_hastad),
        ("低指数小明文", t_small_e_root),
        ("已知 p 高位", t_partial_p),
        ("已知明文高位", t_m_high),
        ("相关消息", t_franklin_reiter),
        ("e 与 phi 不互素", t_e_divides_phi),
    ]
    if "--with-sage" in sys.argv:
        tests += [
            ("p 高位(大参数/Sage)", t_partial_p_sage),
            ("Boneh-Durfee(Sage)", t_boneh_durfee_sage),
        ]
    for _, fn in tests:
        try:
            fn()
        except Exception as exc:
            import traceback

            traceback.print_exc()
            RESULTS.append((fn.__name__, False, False, "EXC", 0.0))

    print()
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r[2])
    print(f"  结果: {passed}/{total} 通过")
    for name, ok, exact, atk, dt in RESULTS:
        if not exact:
            print(f"    - {name}: ok={ok} attack={atk}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
