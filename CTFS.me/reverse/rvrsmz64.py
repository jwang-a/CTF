###Simple Math###
#####Brute force search the limited space of possibilities

import string
import hashlib

flag = [0 for i in range(14)]
flag[0] = 52
flag[1] = 86
flag[2] = 162-flag[1]
flag[3] = (27*14+2)//4
flag[8] = flag[3]
flag[5] = 82
flag[6] = 51
flag[7] = 250970-4919*flag[6]
flag[9] = flag[0]
v4 = (flag[6]^(1337*flag[8]))\
    +flag[1]*(flag[0]^0x539)\
    -(flag[5]^0x539)
v4 = 236807
target = 205903-236807
sol = []
a = list(map(ord,string.printable))
length = len(a)
for i in range(length):
    flag[4] = a[i]
    if flag[4]-15 not in a:
        continue
    flag[10] = flag[4]-15
    for j in range(length):
        flag[11] = a[j]
        for k in range(length):
            flag[12] = a[k]
            flag[13] = flag[11]+flag[12]-95
            if flag[13] not in a:
                continue
            num = -(flag[4]^0x539)\
                    -flag[4]\
                    +(flag[12]^0x539)*flag[13]\
                    +(flag[11]^0x539)*flag[3]\
                    -(flag[1]^0x539)*flag[10]\
                    -(flag[12]^0x539)*flag[0]\
                    -(flag[12]^0x539)*flag[11]\
                    +flag[11]\
                    -(flag[5]^flag[6])%256*flag[10]\
                    +(flag[8]^flag[9])%256*flag[11]
            if num==target:
                sol = ''.join(list(map(chr,flag)))
                m = hashlib.sha1()
                m.update(sol.encode('utf-8'))
                digest = m.hexdigest()
                if 'ce8ee6e1ce91a4aff1b47eba9e6f8c2054fe5239' in digest:
                    print(sol)
                    exit()
