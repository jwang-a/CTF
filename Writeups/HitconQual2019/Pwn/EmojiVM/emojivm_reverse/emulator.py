MI = {0x2796:3,0x2753:5,0x274c:4,0x23ec:0xd,0x274e:0x6,0x2795:0x2,0x1f4af:9,0x1f46b:7,0x1f233:1,0x1f195:0x11,0x1f193:0x12,0x1f21a:0xc,0x1f236:0xb,0x1f480:0x8,0x1f51d:0xe,0x1f4e4:0xf,0x1f4c4:0x13,0x1f4dd:0x14,0x1f4e5:0x10,0x1f522:0x16,0x1f521:0x15,0x1f680:0xa,0x1f6d1:0x17}
OI = {0x1f604:5,0x1f601:1,0x1f600:0,0x1f602:2,0x1f61c:4,0x1f606:7,0x1f605:6,0x1f60a:9,0x1f609:8,0x1f60d:0xa,0x1f923:3}
MINV = {}
OINV = {}
for i in MI.keys():
    MINV[MI[i]] = i
for i in OI.keys():
    OINV[OI[i]] = i


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
        if type(i)==type(0):
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
                #print('jnz')
                if STACK[stack_ptr-1]!=0:
                    code_ptr = STACK[stack_ptr]
                else:
                    code_ptr+=1
                stack_ptr-=2
            elif i==12:
                #print('jz')
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
                    #print(STORAGE[idx1][:STORAGE_SIZE[idx1]])
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
                    #print(STORAGE[idx1][:STORAGE_SIZE[idx1]])
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
                #print(STACK[:stack_ptr])
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
                print(STACK[:stack_ptr+1])
                break
            else:
                print('Invalid command')
                myexit()

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

emojicode = Easm('''
            //Initialize
                //Create table for static symbols
                    push 10
                    create
                    //Storage[0][0] = '*'
                        push 6
                        push 7
                        mult
                        push 0
                        push 0
                        store
                    //Storage[0][1] = '='
                        push 6
                        push 10
                        mult
                        push 1
                        add
                        push 1
                        push 0
                        store
                    //Storage[0][2] = ' '
                        push 4
                        push 8
                        mult
                        push 2
                        push 0
                        store
                //Create table for val1
                    push 1
                    create
                    //Storage[1][0] = 0
                        push 1
                        push 0
                        push 1
                        store
                //Create table fpr val2
                    push 1
                    create
                    //Storage[2][0] = 0
                        push 1
                        push 0
                        push 2
                        store
            //Main algo
                nop
                OUTERLOOP :   offset=56
                    // '\\n'
                        push 10
                    // Storage[0][3] = num1*num2
                        push 0
                        push 1
                        extract
                        push 0
                        push 2
                        extract
                        mult
                        push 3
                        push 0
                        store
                    // Storage[0][4] = 0
                        push 0
                        push 4
                        push 0
                        store
                    //while num1*num2>10 : Storage[0][3]-=10, Storage[0][4]+=1
                        nop
                        nop
                        nop
                        nop
                        nop
                        nop
                        nop
                        nop
                    PARSELOOP :     offset = 90
                        //Storage[0][3]<10
                            push 3
                            push 0
                            extract
                            push 9
                            lt
                        //Storage[0][3]-=10
                            push 10
                            push 3
                            push 0
                            extract
                            sub
                            push 3
                            push 0
                            store
                        //Storage[0][4]+=1
                            push 1
                            push 4
                            push 0
                            extract
                            add
                            push 4
                            push 0
                            store
                        //jmp if false
                            push 9
                            push 10
                            mult
                            jnz
                    //restore the additionally modified value
                        //Stack[top] = Storage[0][3]+10+'0'
                            push 10
                            push 3
                            push 0
                            extract
                            add
                            push 6
                            push 8
                            mult
                            add
                        //Stack[top] = Storage[0][4]+1+'0'
                            push 4
                            push 0
                            extract
                            push 1
                            eq
                            push 3
                            push 0
                            store
                            push 1
                            push 4
                            push 0
                            extract
                            sub
                            push 6
                            push 8
                            mult
                            add
                            push 3
                            push 0
                            extract
                            push 3
                            push 8
                            mult
                            push 8
                            mult
                            jz
                            pop
                            nop
                            nop
                            nop
                            nop
                            nop
                            nop
                        //pop Stack[top] if Stack[top]==0
                        NOPOP : offset = 192
                    // ' '
                        push 2
                        push 0
                        extract
                    // '='
                        push 1
                        push 0
                        extract
                    // ' '
                        push 2
                        push 0
                        extract
                    // '0'+num2
                        push 6
                        push 8
                        mult
                        push 0
                        push 2
                        extract
                        add
                    // ' '
                        push 2
                        push 0
                        extract
                    // '*'
                        push 0
                        push 0
                        extract
                    // ' '
                        push 2
                        push 0
                        extract
                    // '0'+num1
                        push 6
                        push 8
                        mult
                        push 0
                        push 1
                        extract
                        add
                    // printexpression
                        writestack
                    // check if done
                        push 0
                        push 2
                        extract
                        push 1
                        add
                        push 10
                        eq
                        //
                        push 3
                        push 10
                        mult
                        push 10
                        mult
                        push 3
                        add
                        //
                        jz
                        //num2=1
                        push 1
                        push 0
                        push 2
                        store
                        //num1+=1
                        push 0
                        push 1
                        extract
                        push 1
                        add
                        push 0
                        push 1
                        store
                        push 0
                        push 1
                        extract
                        //if num1!=10
                        push 10
                        eq
                        //goto LOOP, else end
                        push 7
                        push 8
                        mult
                        jz
                        end
                        ELSE CASE :   offset = 303
                        //num2+=1; goto LOOP
                        push 0
                        push 2
                        extract
                        push 1
                        add
                        push 0
                        push 2
                        store
                        push 7
                        push 8
                        mult
                        jmp
                 ''')

emojicode = open('chal.evm').read()

assm = []
for i in emojicode:
    i = ord(i)
    if i in MI:
        assm.append(MI[i])
    else:
        assm.append(OI[i])
run(assm)
