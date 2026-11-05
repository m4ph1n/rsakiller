import random
from gmpy2 import *
from Crypto.Util.number import *
FLAG = b'xxx'
f = open('output.txt', 'w+')
print(random.getrandbits(20000), file=f)
random.seed(random.getrandbits(32))
r = lambda x: bytes([random.getrandbits(8)])
P = getPrime(1024, randfunc=r)
Q = getPrime(1024, randfunc=r)
N = P*Q
E = 65537

assert gcd(E, (P-1)*(Q-1)) == 1

print(powmod(bytes_to_long(FLAG), E, N), file=f)
