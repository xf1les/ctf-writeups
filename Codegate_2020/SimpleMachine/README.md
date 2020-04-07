首发：http://blog.leanote.com/post/xp0int/13a88b711311

```
Codegate CTF 2020 Preliminary

Challenge : SimpleMachine

Description :
(fixed-point challenge)

Classic Check Flag Challenge Machine

DOWNLOAD :
http://ctf.codegate.org/099ef54feeff0c4e7c2e4c7dfd7deb6e/116ea16dbeabe08d1fe8891a27d0f16b

point : 333 (80 team solved)
```

## 说明

## 脚本
```
from pwn import *

stage1 = [0xb0bd, 0xbabc, 0xbeb9, 0xbaac, 0xcfce, 0xcfce]
stage2 = [0xf974, 0x2b9d, 0x4caf, 0xbee1, 0xfc0d, 0x6e48, 0xe03c, 0xd322, 0x1979, 0x36d6, 0x40e8, 0xcbf7]
val = 0xdead

flag = ''

for i in stage1:
    flag += p16((0x10000 - i))

next = lambda x:x ^ ((x << 1) & 0xffff)
for i in stage2:
    val = next(val)
    flag += p16((0x10000 - i) ^ val)

# CODEGATE2020{ezpz_but_1t_1s_pr3t3xt}
print flag
```
