from pwn import *
import sys

###Setup
context.log_level = 'critical'
peda = False
cat = 'pygmentize'

if peda is True:
    prompt = '$ '
else:
    prompt = '(gdb) '

###Util
def cmd(command):
    r.sendlineafter(prompt,command)

def start(fname):
    if peda is True:
        r = process(['gdb',fname])
    else:
        r = process(['gdb',fname],env={'HOME':'./'})
    return r

###Debug
filename = sys.argv[1]

r = start(filename[0].upper())

print('=================== source code ===================')
os.system(f'{cat} {filename}.c')

cmd('set exec-wrapper env "LD_PRELOAD=./libc-2.31.so"')
cmd('set disable-randomization off')
cmd('b getchar')
cmd('r')
r.recvline()
print('===================== address =====================')
while True:
    res = r.recvline()
    if b' : ' in res:
        res = res.decode()
        res = res.split(' : ')
        res = '\033[31m'+res[0]+'\033[0m : '+res[1]
        print(res,end='')
    else:
        break
cmd('info proc mappings\n')
while True:
    res = r.recvline()
    if b'heap' in res:
        print('\033[31mheap\033[0m : '+res.split(b'     ')[1].decode())
        break
cmd('printf "main_arena structure : 0x%lx%c",(unsigned long long int)(&__malloc_hook)+0x10,10')
res = r.recvline().decode().split(' : ')
res = '\033[31m'+res[0]+'\033[0m : '+res[1]
print(res,end='')
print('===================================================')
r.interactive()
