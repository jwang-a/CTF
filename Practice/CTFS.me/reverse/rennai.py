###code obfuscation problem###
######tricks of meddling IDApro output
########useless ret
########function with name similar to libc functions


import binascii

cle = (313373133731337//31337)*3
cle = cle^0x4a8255542
cne = 1
v1 = 4196686
DATA = 'CC 08 0C 00 02 00 00 00  95 08 0C 00 02 00 00 00 \
D2 08 0C 00 02 00 00 00  C9 08 0C 00 02 00 00 00 \
91 08 0C 00 02 00 00 00  CA 08 0C 00 02 00 00 00 \
CA 08 0C 00 02 00 00 00  CA 08 0C 00 02 00 00 00 \
CA 08 0C 00 02 00 00 00  FE 08 0C 00 02 00 00 00 \
D1 08 0C 00 02 00 00 00  95 08 0C 00 02 00 00 00 \
95 08 0C 00 02 00 00 00  95 08 0C 00 02 00 00 00 \
95 08 0C 00 02 00 00 00  95 08 0C 00 02 00 00 00 \
95 08 0C 00 02 00 00 00  95 08 0C 00 02 00 00 00 \
95 08 0C 00 02 00 00 00  95 08 0C 00 02 00 00 00 \
95 08 0C 00 02 00 00 00  CA 08 0C 00 02 00 00 00 \
FE 08 0C 00 02 00 00 00  92 08 0C 00 02 00 00 00 \
CA 08 0C 00 02 00 00 00  91 08 0C 00 02 00 00 00 \
91 08 0C 00 02 00 00 00  91 08 0C 00 02 00 00 00 \
91 08 0C 00 02 00 00 00  91 08 0C 00 02 00 00 00 \
91 08 0C 00 02 00 00 00  91 08 0C 00 02 00 00 00 \
91 08 0C 00 02 00 00 00  91 08 0C 00 02 00 00 00 \
91 08 0C 00 02 00 00 00'
DATA = ''.join(DATA.split(' ')[::-1]).replace('000000',' ').split(' ')[::-1][:-1]
v3 = cle^0x54016200
v4 = []
for i in DATA:
    v4.append(int(i,16))
print('CTFS{',end = '')
for i in range(28):
    print(chr(v3^v4[i]),end='')

print('}')