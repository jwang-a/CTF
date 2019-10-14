from pwn import *

###Util
def set_name(data):
    r.sendlineafter('> ','1')
    r.sendafter('name: ',data)

def get_flag():
    r.sendlineafter('> ','4')

def rol(num,shift):
    return ((num<<shift)&0xff)|(num>>shift)

###Constant
target = b'\x11\xde\xcf\x10\xdf\x75\xbb\xa5\x43\x1e\x9d\xc2\xe3\xbf\xf5\xd6\x96\x7f\xbe\xb0\xbf\xb7\x96\x1d\xa8\xbb\x0a\xd9\xbf\xc9\x0d\xff'
key =    b'\x55\x48\x89\xe5\x48\x83\xec\x50\x64\x48\x8b\x04\x25\x28\x00\x00\x00\x48\x89\x45\xf8\x31\xc0\xe8\x24\xfe\xff\xff\x48\x8d\x45\xc0'

###Exploit
r = remote('svc.pwnable.xyz',30031)

name = b''
for i in range(0x20):
    name+=p8(rol(target[i]^key[i],4))

set_name(name)
get_flag()
r.interactive()
