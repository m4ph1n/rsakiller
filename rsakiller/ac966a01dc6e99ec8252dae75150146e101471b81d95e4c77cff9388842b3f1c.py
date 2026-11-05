from Crypto.Util.number import *
import binascii
import gmpy2
flag = '*****************************************'
hex_flag=int(flag.encode("hex"),16)

p=getPrime(256)
q=getPrime(256)
n=p*q

e=getPrime(100)

c=pow(hex_flag,e,n)

p=((p>>60)<<60)

print("n=",hex(n))
print("p=",hex(p))
print("e=",hex(e))
print("c=",hex(c))
'''
('n=', '0x558477ce1d081f831cfa159290ee4fd14888422c216a16ad86e2b2d4335e3cb18ed0120a955f970b17b229a8e7d0ae1b6f0c40213ad0e127eba99ae0d8a82397L')
('p=', '0x8fbcbb7d1e9f393ee21b537d6e0bd2cf8629e315f4e356c1e000000000000000L')
('e=', '0xf7278179324b11fd83d08aa6fL')
('c=', '0x36e1c09ccad45cd63a0f07e704d3811c39d70cdfdad999d2df90255a76c58cf6fe99ac1ab1d5d99a4ce1a2ebdbfbc49ce72df2a0b90766ff84ab0ef62068d46bL')

'''





