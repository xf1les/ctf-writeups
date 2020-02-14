中文：http://blog.leanote.com/post/xp0int/Halffeed

## Challenge
```
Codegate CTF 2020 Preliminary

Challenge : Halffeed

Description :
nc 110.10.147.44 7777

DOWNLOAD :
http://ctf.codegate.org/099ef54feeff0c4e7c2e4c7dfd7deb6e/9a7f846af14e09f6b32cff3a648b80f5

point : 670 (43 team solved)
```

## Solution
Let<img src="https://render.githubusercontent.com/render/math?math=P_0 =">`AAAAAAAAAAAAAAAA`, <img src="https://render.githubusercontent.com/render/math?math=P_0' =">`BBBBBBBBBBBBBBBB`, <img src="https://render.githubusercontent.com/render/math?math=P_1 =">`;cat flag;AAAAAA` and <img src="https://render.githubusercontent.com/render/math?math=n=0">.

1. Encrypt `'\x00' * 16`, <img src="https://render.githubusercontent.com/render/math?math=P_0%2B">`'\x00' * 16` and <img src="https://render.githubusercontent.com/render/math?math=P_0'%2B">`'\x00' * 16` with nonce <img src="https://render.githubusercontent.com/render/math?math=n">, take the last 16 bytes of each ciphertexts as <img src="https://render.githubusercontent.com/render/math?math=T_0">, <img src="https://render.githubusercontent.com/render/math?math=T_1">, and<img src="https://render.githubusercontent.com/render/math?math=T_1'">.
2. Compute ciphertext <img src="https://render.githubusercontent.com/render/math?math=C=XOR(P_0%2BP_1,T_0%2BT_1)">
3. Compute <img src="https://render.githubusercontent.com/render/math?math=t_2 = XOR(T_1[:8],P_1[:8])%2BP_1[8:]">, <img src="https://render.githubusercontent.com/render/math?math=P_1' = XOR(T_1'[:8],t_2[:8])%2Bt_2[8:]">
4. Encrypt <img src="https://render.githubusercontent.com/render/math?math=P_0'%2BP_1'"> with nonce <img src="https://render.githubusercontent.com/render/math?math=n">, got tag <img src="https://render.githubusercontent.com/render/math?math=T">.
5. Submit <img src="https://render.githubusercontent.com/render/math?math=n">, <img src="https://render.githubusercontent.com/render/math?math=C">, <img src="https://render.githubusercontent.com/render/math?math=T"> and get the flag.

## Introduction

We get two Python scripts from the extracted zip file: `halffeed.py` implements a simplified version of [mixFeed](https://csrc.nist.gov/CSRC/media/Projects/Lightweight-Cryptography/documents/round-1/spec-doc/mixFeed-spec.pdf) encryption algorithm which is a lightweight [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) block cipher based on AES-128, `prob.py` is the main program that we  can communicate with via remote connection.

The menu of the main program:

```
1) Encrypt
2) Decrypt
3) Execute
4) Exit
>
```

`Encrypt` inputs a hex string as *plaintext* and output the corresponding *ciphertext* and *tag*. If the *plaintext* contains a substring `cat flag` the program will print out an error and exit.

```python
# prob.py L19-L31
def encrypt(halffeed):
    global nonce
    P = recv_data('plaintext')

    if b'cat flag' in P:
        print('[EXCEPTION] Invalid Command "cat flag"')
        exit()

    C, T = halffeed.encrypt(nonce.to_bytes(16, byteorder='big'), P)

    send_data('ciphertext', C)
    send_data('tag', T)
    nonce += 1
```
* *tag* acts as a kind of [Message authentication code (MAC)](https://en.wikipedia.org/wiki/Message_authentication_code), so *ciphertext* can be authenticated and rejected if *tag* or/and *ciphertext* is invaild.

* *nonce* is an integer used to prevent replay attack. With different *nonce* same *plaintext* can be transformed to different *ciphertext*. (See this [Wikipedia page](https://en.wikipedia.org/wiki/Cryptographic_nonce) for more details)

`Execute` decrypts ciphertext and split the plaintext into multiple substrings by delimiter `;`. If one of substrings equals `cat flag` the program will give us flag.

```python
# prob.py L54-L71
def execute(halffeed):
    N = recv_data('nonce')
    C = recv_data('ciphertext')
    T = recv_data('tag')

    P = halffeed.decrypt(N, C, T)

    if P is not None:
        cmds = P.split(b';')
        for cmd in cmds:
            if cmd.strip() == b'cat flag':
                with open('./flag') as f:
                    print(f.read())
            else:
                print('[EXCEPTION] Unknown Command')
    else:
        print('[EXCEPTION] Authentication Failed')
    exit()
```
The code shown above from `prob.py` describes how the encryption algorithm works when the length of *plaintext* is the multiple of 16. To make the code easier to read, some parts of code such as block padding are removed.

```python
def feed_plus(self, tag, data):
    enc_data = bytes(b1 ^ b2 for b1, b2 in zip(tag, data))
    tag = enc_data[:8] + data[8:]

    return tag, enc_data

def encrypt(self, nonce, plaintext):
    Kn, _ = aes_encrypt(self.key, nonce)
    T, K = aes_encrypt(Kn, nonce)

    ciphertext = b''
    for i in range(0, len(plaintext), 16):
        T, block = self.feed_plus(T, plaintext[i:i+16])
        ciphertext += block
        T, K = aes_encrypt(K, T)

    T, _ = aes_encrypt(K, T)

    return ciphertext, T
```

1. Generate <img src="https://render.githubusercontent.com/render/math?math=T_0">, <img src="https://render.githubusercontent.com/render/math?math=K_0"> from master key (read from `secretkey` file) and given *nonce*.
2. Divide plaintext <img src="https://render.githubusercontent.com/render/math?math=P"> into 16-bytes blocks <img src="https://render.githubusercontent.com/render/math?math=P_0">, <img src="https://render.githubusercontent.com/render/math?math=P_1">, <img src="https://render.githubusercontent.com/render/math?math=P_2">, ..., <img src="https://render.githubusercontent.com/render/math?math=P_n">.
3. Compute ciphertext block <img src="https://render.githubusercontent.com/render/math?math=C_0=XOR(P_0,T_0)">.
4. Calculate pre-tag <img src="https://render.githubusercontent.com/render/math?math=t_1=C_0[:8]%2BP_0[8:]">.
5. Encrypt <img src="https://render.githubusercontent.com/render/math?math=t_1">, <img src="https://render.githubusercontent.com/render/math?math=K_0"> with key <img src="https://render.githubusercontent.com/render/math?math=K_0"> using AES-128, got ciphertext <img src="https://render.githubusercontent.com/render/math?math=T_1">, <img src="https://render.githubusercontent.com/render/math?math=K_1">.
6. Repeat Step 3 to 5 until all plaintext blocks are encrypted.
7. Encrypt <img src="https://render.githubusercontent.com/render/math?math=T_{n%2b1}"> with key <img src="https://render.githubusercontent.com/render/math?math=K_{n%2b1}">, then output ciphertext <img src="https://render.githubusercontent.com/render/math?math=T"> as *tag* and <img src="https://render.githubusercontent.com/render/math?math=C_0">, <img src="https://render.githubusercontent.com/render/math?math=C_1">, <img src="https://render.githubusercontent.com/render/math?math=C_2">, ..., <img src="https://render.githubusercontent.com/render/math?math=C_n"> as *ciphertext*.

## Exploit

My solution is collecting some intermediate values used in encryption to achieve arbitrary plaintext encryption. We can construct special plaintexts and leak values from their ciphertexts and tags.

First of all, *nonce* used for encryption must be same. In `prob.py`, the initial *nonce* is a fixed value 0 and we can easily reuse it by opening multiple connections and encrypting one plaintext per connection.

Computing *ciphertext* is easy. It's just simply XORing plaintext blocks with
<img src="https://render.githubusercontent.com/render/math?math=T_x"> which can be leaked by a plaintext block filled with null byte `\x00`.

Generating *tag* is diffcult because we can't leak the keys used to generate it. After exploring the algorithm, I finally find an approach to do this: construct a different plaintext with the same *tag*.

For example, there are three plaintext blocks <img src="https://render.githubusercontent.com/render/math?math=P_0">, <img src="https://render.githubusercontent.com/render/math?math=P_0'">and <img src="https://render.githubusercontent.com/render/math?math=P_1">, we are able to find another plaintext block<img src="https://render.githubusercontent.com/render/math?math=P_1'">so <img src="https://render.githubusercontent.com/render/math?math=P_0P_1"> and <img src="https://render.githubusercontent.com/render/math?math=P_0'P_1'"> have the same *tag*.

Let's track down and see how *tag* <img src="https://render.githubusercontent.com/render/math?math=T"> and  <img src="https://render.githubusercontent.com/render/math?math=T'">is generated:

* <img src="https://render.githubusercontent.com/render/math?math=T{\leftarrow}T_2{\leftarrow}t_2=C_1[:8]%2bP_1[8:]=XOR(T_1[:8],P_1[:8])%2bP_1[8:]">

* <img src="https://render.githubusercontent.com/render/math?math=T'{\leftarrow}T_2'{\leftarrow}"><img src="https://render.githubusercontent.com/render/math?math=t_2'="><img src="https://render.githubusercontent.com/render/math?math=C_1'[:8]%2bP_1'[8:]=XOR(T_1'[:8],P_1'[:8])%2bP_1'[8:]">

So <img src="https://render.githubusercontent.com/render/math?math=T=T'{\rightarrow}t_2'=t_2">. Then given leaked <img src="https://render.githubusercontent.com/render/math?math=T_1">, <img src="https://render.githubusercontent.com/render/math?math=T_1'">, we can calculate <img src="https://render.githubusercontent.com/render/math?math=t_2"> and <img src="https://render.githubusercontent.com/render/math?math=P_1'">:

* <img src="https://render.githubusercontent.com/render/math?math=t_2=XOR(T_1[:8],P_1[:8])%2bP_1[8:]">

* <img src="https://render.githubusercontent.com/render/math?math=P_1'=XOR(T_1'[:8],t_2[:8])%2bt_2[8:]">

Here is the exploit script:

```python
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
```
