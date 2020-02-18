from pwn import *

###Structure
'''
BPF
    |   1   |   1   |   1   |   1   |   1   |   1   |   1   |   1   |
0x00|     code      | field1| field2|         generic_field         |

code(bits)
generic
    |   1   |   1   |   1   |   1   |   1   |   1   |   1   |   1   |
0x00|   instruction_class   | source|         operation_code        |
BPF_LD/BPF_LDX/BPF_ST/BPF_STX
0x00|   instruction_class   |      size     |          mode         |

instructions class:
    class0 -> BPF_LD
        if mode==0x00:
            A = generic_field
        else if mode==0x20:
            A = data[generic_field]
        else if mode==0x60:
            A = mem[generic_field]
        else:
            undefined
        **missing BPF_LEN(0x80)**
    class1 -> BPF_LDX
        if mode==0x00:
            X = generic_field
        else if mode==0x20:
            X = data[generic_field]         **not allowed in seccomp bpf**
        else if mode==0x60:
            X = mem[generic_field]
        else:
            undefined
        **missing BPF_LEN(0x80)**
    class2 -> BPF_ST
        mem[generic_field] = A
    class3 -> BPF_STX
        mem[generic_field] = X
    class4 -> BPF_ALU
        if source!=0:
            target = X
        else:
            target = generic_field
        if operation_code==0x00:
            A += target
        else if operation_code==0x10:
            A -= target
        else if operation_code==0x20:
            A *= target
        else if operation_code==0x30:
            A /= target
        else if operation_code==0x40:
            A |= target
        else if operation_code==0x50:
            A &= target
        else if operation_code==0x60:
            A <<= target
        else if operation_code==0x70:
            A >>= target
        else if operation_code==0x80:
            A = -A
        else if operation_code==0xa0:
            A ^= target
        else:
            undefined
    class5 -> BPF_JMP
        if source!=0:
            target = X
        else:
            target = generic_field
        if operation_code==0x00:
            jmp generic_field
        else if operation_code==0x10:
            A == target ? jmp field1 : jmp field2
        else if operation_code==0x20:
            A > target ? jmp field1 : jmp field2
        else if operation_code==0x30:
            A >= target ? jmp field1 : jmp field2
        else if operation_code==0x40:
            A & target ? jmp field1 : jmp field2
        else:
            ignore
    class6 -> BPF_RET   (seems strange?)
        if source==0 and operation_code&0x10==0x10:
            return A
        else:
            return generic_field
    class7 -> BPF_MISC
        if operation_code&0x80!=0:
            A=X
        else:
            X=A
'''

BPF_LD=0x0
BPF_LDX=0x1
BPF_ST=0x2
BPF_STX=0x3
BPF_ALU=0x4
BPF_JMP=0x5
BPF_RET=0x6
BPF_MISC=0x7

BPF_K=0x0
BPF_X=0x8

BPF_IMM=0x00
BPF_ABS=0x20
BPF_MEM=0x60
BPF_LEN=0x80

BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10

BPF_ADD=0x00
BPF_SUB=0x10
BPF_MUL=0x20
BPF_DIV=0x30
BPF_OR=0x40
BPF_AND=0x50
BPF_LSH=0x60
BPF_RSH=0x70
BPF_NEG=0x80
BPF_XOR=0xa0

BPF_JA=0x00
BPF_JEQ=0x10
BPF_JGT=0x20
BPF_JGE=0x30
BPF_JSET=0x40

def BPFasm(assembly):
    assembly = assembly.strip().split('\n')
    bytecode = b''
    for line in assembly:
        origline=line
        code=None
        jmp1=0
        jmp2=0
        generic=0
        line = line.split('//')[0].strip()
        if line=='':
            continue
        line = line.split()
        if line[0]=='loadA':
            if line[1][:4]=='data':
                code = BPF_LD|BPF_ABS
                generic = int(line[1].split('[')[1].split(']')[0])
            elif line[1][:3]=='mem':
                code = BPF_LD|BPF_MEM
                generic = int(line[1].split('[')[1].split(']')[0])
            elif line[1][:3]=='len':
                code = BPF_LD|BPF_LEN
            else:
                code = BPF_LD|BPF_IMM
                generic = int(line[1])
        elif line[0]=='loadX':
            if line[1][:3]=='mem':
                code = BPF_LDX|BPF_MEM
                generic = int(line[1].split('[')[1].split(']')[0])
            elif line[1][:3]=='len':
                code = BPF_LDX|BPF_LEN
            else:
                code = BPF_LDX|BPF_IMM
                generic = int(line[1])
        elif line[0]=='storeA':
            code = BPF_ST
            generic = int(line[1].split('[')[1].split(']')[0])
        elif line[0]=='storeX':
            code = BPF_STX
            generic = int(line[1].split('[')[1].split(']')[0])
        elif line[0]=='add':
            if line[1]=='X':
                code = BPF_ALU|BPF_ADD|BPF_X
            else:
                code = BPF_ALU|BPF_ADD|BPF_K
                generic = int(line[1])
        elif line[0]=='sub':
            if line[1]=='X':
                code = BPF_ALU|BPF_SUB|BPF_X
            else:
                code = BPF_ALU|BPF_SUB|BPF_K
                generic = int(line[1])
        elif line[0]=='mul':
            if line[1]=='X':
                code = BPF_ALU|BPF_MUL|BPF_X
            else:
                code = BPF_ALU|BPF_MUL|BPF_K
                generic = int(line[1])
        elif line[0]=='div':
            if line[1]=='X':
                code = BPF_ALU|BPF_DIV|BPF_X
            else:
                code = BPF_ALU|BPF_DIV|BPF_K
                generic = int(line[1])
        elif line[0]=='or':
            if line[1]=='X':
                code = BPF_ALU|BPF_OR|BPF_X
            else:
                code = BPF_ALU|BPF_OR|BPF_K
                generic = int(line[1])
        elif line[0]=='and':
            if line[1]=='X':
                code = BPF_ALU|BPF_AND|BPF_X
            else:
                code = BPF_ALU|BPF_AND|BPF_K
                generic = int(line[1])
        elif line[0]=='shl':
            if line[1]=='X':
                code = BPF_ALU|BPF_LSH|BPF_X
            else:
                code = BPF_ALU|BPF_LSH|BPF_K
                generic = int(line[1])
        elif line[0]=='shr':
            if line[1]=='X':
                code = BPF_ALU|BPF_RSH|BPF_X
            else:
                code = BPF_ALU|BPF_RSH|BPF_K
                generic = int(line[1])
        elif line[0]=='neg':
            code = BPF_ALU|BPF_NEG
        elif line[0]=='xor':
            if line[1]=='X':
                code = BPF_ALU|BPF_XOR|BPF_X
            else:
                code = BPF_ALU|BPF_XOR|BPF_K
                generic = int(line[1])
        elif line[0]=='jmp':
            code = BPF_JMP|BPF_JA
            generic = int(line[1])
        elif line[0][0]=='j':
            if line[0]=='jeq' or line[0]=='jne':
                code = BPF_JMP|BPF_JEQ
            if line[0]=='jgt' or line[0]=='jle':
                code = BPF_JMP|BPF_JGT
            if line[0]=='jge' or line[0]=='jlt':
                code = BPF_JMP|BPF_JGE
            if line[0]=='jset' or line[0]=='jnset':
                code = BPF_JMP|BPF_JSET
            if code is not None:
                if line[1]=='X':
                    code|=BPF_X
                else:
                    code|=BPF_K
                    generic = int(line[1])
            if line[0]=='jeq' or line[0]=='jgt' or line[0]=='jge' or line[0]=='jset':
                jmp1 = int(line[2])
            else:
                jmp2 = int(line[2])
        elif line[0]=='ret':
            if line[1]=='A':
                code = BPF_RET|0x10
            else:
                code = BPF_RET
                if line[1]=='KILL' or line[1]=='KILL_THREAD':
                    generic = 0
                elif line[1]=='TRAP':
                    generic = 0x30000
                elif line[1][:5]=='ERRNO':
                    generic = 0x50000|int(line[1].split('(')[1].split(')')[0])
                elif line[1]=='TRACE':
                    generic = 0x7ff00000
                elif line[1]=='ALLOW':
                    generic = 0x7fff0000
                elif line[1]=='KILL_PROCESS':
                    generic = 0x80000000
        elif line[0]=='mov':
            if line[1][0]=='A':
                code = BPF_MISC|0x80
            else:
                code = BPF_MISC
        if code is None:
            print(f'Error at line : {origline}')
        bytecode+=p16(code)+p8(jmp1)+p8(jmp2)+p32(generic)
    return bytecode
