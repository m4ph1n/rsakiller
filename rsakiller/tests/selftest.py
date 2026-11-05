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
        # e 与 phi 不互素时，满足 m^e ≡ c 的明文有多个，工具只能做启发式挑选。
        # 真值落在候选集里就说明这类题解出来了，挑得准不准是另一回事。
        if not exact and res and res.candidates:
            exact = (expect % ctx.n) in {cand % ctx.n for cand in res.candidates}
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
    """e 与 phi 不互素：需要先求 e 次根，再用 e/g 解密。

    纯 Python 的 AMM 只能处理 gcd(e, (p−1)/e) = 1 的情形（3 | p−1 但 9 ∤ p−1）。
    9 | p−1 时必须由 Sage 的 nth_root 补上，所以纯 Python 模式下改取
    能解的那一档 —— 否则测的是一个已知的能力边界，而不是回归。
    """
    if "--no-sage" in sys.argv:
        # gcd(3, (p−1)/3) = 1：AMM 可解
        while True:
            p = getPrime(512)
            if (p - 1) % 3 == 0 and (p - 1) % 9 != 0:
                break
    else:
        # 9 | p−1：纯 Python 无解，必须走 Sage 的 nth_root。
        # 这一档要生成 9 | p−1 的素数，外加一次 Sage 冷启动，明显比其他项慢。
        while True:
            p = getPrime(256)
            if (p - 1) % 9 == 0:
                break
    q = getPrime(512 if "--no-sage" in sys.argv else 256)
    n = p * q
    e = 3
    # 明文要足够大，否则会被"低指数小明文"直接开方，测不到 AMM 分支
    m = (m_of(FLAG) << 200) | rand_int(200)
    assert m ** 3 > n
    c = U.powmod(m, e, n)
    check("e 与 phi 不互素", RSAContext(n=n, e=e, c=c, p=p, q=q), m)


# ---------------------------------------------------------------- 补齐的题型
def t_known_phi():
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e = 65537
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("已知 phi", RSAContext(n=n, e=e, c=c, phi=(p - 1) * (q - 1)), m)


def t_rsa_crt_fault():
    """RSA-CRT 签名里有一半算错：gcd(s'^e - m, n) 直接给出因子。"""
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    msg = U.bytes_to_long(b"rsa-crt-fault-test")
    dp, dq = d % (p - 1), d % (q - 1)
    qi = U.inv(p, q)
    sig_p = pow(msg, dp, p)
    # 故意把 q 那一半算错，模拟硬件故障
    sig_q_bad = (pow(msg, dq, q) + 1) % q
    faulty = (sig_p + p * ((sig_q_bad - sig_p) * qi % q)) % n
    assert pow(faulty, e, n) != msg % n
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("RSA-CRT 故障签名", RSAContext(n=n, e=e, c=c, sig=faulty, signed_msg=msg), m)


def t_non_rsa_prime():
    import gmpy2

    n = int(gmpy2.next_prime(getPrime(512)))    # n 本身是素数
    e = 65537
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("n 是素数", RSAContext(n=n, e=e, c=c), m)


def t_non_rsa_prime_power():
    p = getPrime(128)
    n = p ** 5
    e = 65537
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("n = p^k", RSAContext(n=n, e=e, c=c), m)


def t_fermat_multiplier():
    """q ≈ 5p：两个因子差一个 5 倍关系，普通 Fermat 抓不到。"""
    import gmpy2

    p = getPrime(256)
    q = int(gmpy2.next_prime(5 * p))
    n = p * q
    e = 65537
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("p、q 成小倍数", RSAContext(n=n, e=e, c=c), m)


def t_sequence_gcd():
    """p 取成 Fibonacci 素数。"""
    import gmpy2

    fib = [1, 1]
    while fib[-1].bit_length() < 120:
        fib.append(fib[-1] + fib[-2])
    pf = [f for f in fib if U.is_probable_prime(f)][-1]
    q = getPrime(128)
    n = pf * q
    e = 65537
    m = m_of(FLAG)
    c = U.powmod(m, e, n)
    check("p 是 Fibonacci 数", RSAContext(n=n, e=e, c=c), m)


def t_special_carmichael():
    """Carmichael 数：普通试除/rho 都抓不到，靠 Miller-Rabin 链上的非平凡平方根。

    这类 n 有多个素因子，phi 与 n 同量级但可完全写出；e 必须与 phi 互素，
    否则连私钥都不存在。561 = 3·11·17，phi = 320 = 2^6·5，故 e 取奇数。
    """
    n = 561
    phi = 320
    e = 7
    assert U.gcd(e, phi) == 1
    m = U.bytes_to_long(FLAG) % n
    c = U.powmod(m, e, n)
    check("Carmichael 数", RSAContext(n=n, e=e, c=c), m)


def t_stereotyped_suffix():
    """已知明文前缀与后缀，中间一段未知。

    未知部分必须满足 X < N^(1/e)：e = 3 时上界约 n 的三分之一位宽。
    同时整条明文要够大（靠足够长的后缀撑起来），否则会被
    "低指数小明文直接开方"抢先解掉，就测不到 stereotyped 分支了。
    """
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e = 3
    prefix = b"flag{"
    suffix = b"}" + b"P" * 48          # 长后缀把 m 抬到 m^3 > n
    unknown = U.long_to_bytes(0xDEADBEEFCAFE1234567890ABCDEF) + b"\x01" * 3
    m = U.bytes_to_long(prefix + unknown + suffix)
    assert m ** 3 > n
    c = U.powmod(m, e, n)
    check("已知前后缀", RSAContext(n=n, e=e, c=c), m,
          Options(online=False, m_prefix=prefix.decode(), m_suffix=suffix.decode(),
                  m_unknown_len=len(unknown)))


def t_short_pad():
    """两条密文的明文只差一个很小的未知量。

    Coppersmith 求 δ^e 需要多轮 LLL，单次约一分钟，属于慢题。
    """
    p, q = getPrime(512), getPrime(512)
    n = p * q
    e = 3
    m1 = (m_of(FLAG) << 200) | rand_int(200)
    m2 = m1 + 12345
    assert m1 ** 3 > n
    c1, c2 = U.powmod(m1, e, n), U.powmod(m2, e, n)
    check("短填充", RSAContext(n=n, e=e, c=c1, cs=[c1, c2]), m1)


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
        ("已知 phi", t_known_phi),
        ("dp 泄露", t_dp_leak),
        ("RSA-CRT 故障", t_rsa_crt_fault),
        ("小素因子", t_small_q),
        ("多模数共享因子", t_common_factor),
        ("p、q 接近", t_fermat),
        ("p、q 成小倍数", t_fermat_multiplier),
        ("n 是素数", t_non_rsa_prime),
        ("n = p^k", t_non_rsa_prime_power),
        ("Carmichael 数", t_special_carmichael),
        ("Fibonacci 素数", t_sequence_gcd),
        ("小私钥 d", t_wiener),
        ("共模攻击", t_common_modulus),
        ("低指数广播", t_hastad),
        ("低指数小明文", t_small_e_root),
        ("已知 p 高位", t_partial_p),
        ("已知明文高位", t_m_high),
        ("已知前后缀", t_stereotyped_suffix),
        ("相关消息", t_franklin_reiter),
        ("短填充", t_short_pad),
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
