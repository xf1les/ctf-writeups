from pwn import *

context(log_level="debug")

def xor(j, k):
    return ''.join([chr(b1 ^ b2) for b1, b2 in zip(map(ord, j), map(ord, k))])

def feed_plus_tag(tag, data):
    enc_data = xor(tag, data)
    tag = enc_data[:8] + data[8:]

    return tag

def enc(P):
    p = remote("110.10.147.44", 7777)
    p.sendlineafter("> ", '1')
    p.sendlineafter("plaintext =", P.encode('hex'))
    p.recvuntil("ciphertext = ")
    c = p.recvline().strip().decode('hex')
    p.recvuntil("tag = ")
    t = p.recvline().strip().decode('hex')
    p.close()

    return c, t

def getflag(n, c, t):
    n = p64(n, endian="big").rjust(16, '\x00')

    p = remote("110.10.147.44", 7777)
    p.sendlineafter("> ", '3')
    p.sendlineafter("nonce =", n.encode('hex'))
    p.sendlineafter("ciphertext =", c.encode('hex'))
    p.sendlineafter("tag =", t.encode('hex'))

    p.interactive()

def leak_tag(p):
    c, _ = enc(p + '\x00' * 16)
    return c[-16:]

P0  = 'A' * 16
P0_ = 'B' * 16
P1  = ";cat flag;".ljust(16, 'A')

T0  = leak_tag('')
T1  = leak_tag(P0)
T1_ = leak_tag(P0_)
forge_ciphertext = xor(P0 + P1, T0 + T1)

t2 = feed_plus_tag(T1, P1)
P = P0_ + feed_plus_tag(T1_, t2)
_, forge_tag = enc(P)

# CODEGATE2020{F33D1NG_0N1Y_H4LF_BL0CK_W1TH_BL0CK_C1PH3R}
getflag(0, forge_ciphertext, forge_tag)
