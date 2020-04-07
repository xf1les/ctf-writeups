首发：http://blog.leanote.com/post/xp0int/%5BCrypto%5D-randomstudy

一共有三个与随机数有关的挑战。

第一关和第三关涉及 Python 的`Random`模块，随机种子 seed 是 Unix 时间戳。由于时间戳只精确到秒，只要速度够快，就能获得跟远程机器一样的 seed。

第三关涉及 Java 的`Random`模块（即`java.util.Random`）。该模块生成的随机数十分不安全，目前已经被`SecureRandom`模块代替。

随机数生成算法：

```
seed = 0xdeadbeefdead
def prng():
    global seed
    seed = (seed * 0x5DEECE66DL + 0xBL) & 0xFFFFFFFFFFFF
    return seed >> 16

rand0 = prng()
rand1 = prng()
rand2 = prng()
.....
```
原理很简单：首先设定一个48位初始 seed，先按照算法计算出新 seed，再取其前32位作为随机数，然后不断重复循环生成。因为随机数就是 seed 的前32位，只要能知道两个连续生成的随机数，就能爆破后16位获取完整的  seed，从而预测后续生成的随机数。

脚本如下：

```
#from pwn_works import *
from pwn import *
from hashlib import sha256
from itertools import product
import time
import random

context(log_level="debug")

def java_rand_predict(v1, v2):
    def prng(seed):
        return ((seed * 0x5DEECE66DL + 0xBL) & ((1 << 48) - 1))
    
    def t32(i):
        if i >> 31:
            return -((1 << 32) - i)
        return i
    
    def f32(i):
        if i < 0:
            return (1 << 32) + i
        return i

    v1 = f32(v1)
    v2 = f32(v2)

    for i in range(0, 1 << 16):
        s = (v1 << 16) + i;
        if prng(s) >> 16 == v2:
            return t32(prng(prng(s)) >> 16)

#p_run("119.3.245.36:23456")

target = remote("119.3.245.36", 23456)

target.recvuntil("hexdigest()=")
sha1hash = target.recv(64)
target.recvuntil("encode('hex')=")
skr = target.recv(10).decode('hex')

for i in product(range(0, 0x100), repeat=3):
    val = skr + ''.join(map(chr, i))
    if sha256(val).hexdigest() == sha1hash:
        target.sendline(val.encode('hex'))
        break

target.sendline('2535753c4e39491b79d8c0273f164c4b')

random.seed(int(time.time()))
target.recvuntil("[+]Generating challenge 1")
target.sendlineafter("[-]", str(random.randint(0, 2**64)))

target.recvuntil("[+]Generating challenge 2")
while 1:
    target.recvuntil("[-]")
    v1 = int(target.recvline())
    target.recvuntil("[-]")
    v2 = int(target.recvline())

    v3 = java_rand_predict(v1, v2)
    if v3:
        target.sendlineafter("[-]", str(v3))
        break
    else:
        target.sendlineafter("[-]", '0')

target.recvuntil("[+]Generating challenge 3")
target.sendlineafter("[-]", str(random.getrandbits(32)))

target.interactive()

"""
[+] Opening connection to 119.3.245.36 on port 23456: Done
[DEBUG] Received 0x1b bytes:
    '[+]proof: skr=os.urandom(8)'
[DEBUG] Received 0x9f bytes:
    '\n'
    '[+]hashlib.sha256(skr).hexdigest()=5df39ff5889d737dda44aab0a754ecf3aff5f332be24d30848491126627e070d\n'
    "[+]skr[0:5].encode('hex')=30322a130e\n"
    "[-]skr.encode('hex')="
[DEBUG] Sent 0x11 bytes:
    '30322a130e737198\n'
[DEBUG] Sent 0x21 bytes:
    '2535753c4e39491b79d8c0273f164c4b\n'
[DEBUG] Received 0xd bytes:
    '[+]teamtoken:'
[DEBUG] Received 0x33 bytes:
    '[++++++++++++++++]proof completed[++++++++++++++++]'
[DEBUG] Received 0xa5 bytes:
    '\n'
    '[+]code\n'
    '> import librandomstudy\n'
    '> librandomstudy.challenge1()\n'
    '> librandomstudy.challenge2()\n'
    '> librandomstudy.challenge3()\n'
    '> print flag\n'
    '[+]Generating challenge 1\n'
    '[-]'
[DEBUG] Sent 0x15 bytes:
    '13219177940997269146\n'
[DEBUG] Received 0x39 bytes:
    '[++++++++++++++++]challenge 1 completed[++++++++++++++++]'
[DEBUG] Received 0x38 bytes:
    '\n'
    '[+]Generating challenge 2\n'
    '[-]1892282686\n'
    '[-]83613792\n'
    '[-]'
[DEBUG] Sent 0x9 bytes:
    '91017476\n'
[DEBUG] Received 0x39 bytes:
    '[++++++++++++++++]challenge 2 completed[++++++++++++++++]'
[DEBUG] Received 0x1e bytes:
    '\n'
    '[+]Generating challenge 3\n'
    '[-]'
[DEBUG] Sent 0xb bytes:
    '3820151750\n'
[*] Switching to interactive mode
[DEBUG] Received 0x39 bytes:
    '[++++++++++++++++]challenge 3 completed[++++++++++++++++]'
[++++++++++++++++]challenge 3 completed[++++++++++++++++][DEBUG] Received 0x76 bytes:
    '\n'
    '[++++++++++++++++]all clear[++++++++++++++++]\n'
    'flag{aeab8f5b7ab5e23f71e80de067e28a45abd05f426c5a91063be36539257f9170}\n'

[++++++++++++++++]all clear[++++++++++++++++]
flag{aeab8f5b7ab5e23f71e80de067e28a45abd05f426c5a91063be36539257f9170}
[*] Got EOF while reading in interactive
"""
```
