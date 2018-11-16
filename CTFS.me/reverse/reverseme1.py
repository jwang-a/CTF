###simple calculative reverse###

import binascii

a1 = [0x34,0xd6,0xc3,0x80,0xc8,0xd7,0x92,0x21,0x85,0x1f,0xe7,0xa6,0x35,0x25,0x36,0x92]
a2 = 0x10
a3 = 0
a5 = 14

v21 = [0 for i in range(256)]
v5 = 0
for i in range(256):
    v21[i] = i

v6 = 0
v7 = 0
v8 = 0
for i in range(256):
    v9 = a1[v7]
    v7+=1
    v10 = v21[v6]
    v8 += v9+(v21[v6]&0xff)
    if v8>0x7fffffff:
        print('boo')
        exit()
    if v7>=a2:
        v7 = 0
    v6+=1
    v8 = v8&0xff
    v21[v6-1] = v21[v8]
    v21[v8] = v10

result = 0
v13 = 0
code = []
for i in range(a5):
    v18 = (v13+1)&0xff
    v19 = v21[v18]
    v13+=1
    v20 = (v19+result)&0xff
    result = (v19+result)&0xff
    v21[v18] = v21[v20]
    v21[v20] = v19
    code.append(v21[(v21[v18]+v19)&0xff])


chk = [0x6f,0xfa,0x29,0xcd,0x45,0xf2,0xdd,0x85,0xe0,0x2c,0x5a,0x1c,0x43,0x6e]
for i in range(a5):
    print(chr(code[i]^chk[i]),end='')
print('')
