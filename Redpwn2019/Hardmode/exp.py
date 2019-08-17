###FLAG is evil = =

from pwn import *

r = remote('chall.2019.redpwn.net',4002)
r.sendlineafter('challenge\n','M30W')
r.interactive()
