###Parses memory dump into binary
#  Ignores value changes & Str tables since they are not necessary in static analysis with IDA

from pwn import *

f = open('Rbin','rb').read()

PHToffset = u64(f[0x20:0x28])
PHTsize = u16(f[0x36:0x38])
PHTentrycnt = u16(f[0x38:0x3a])

SHToffset = u64(f[0x28:0x30])
SHTsize = u16(f[0x3a:0x3c])
SHTentrycnt = u16(f[0x3c:0x3e])

FILE = []
for i in range(PHTentrycnt):
    PHTentry = f[PHToffset+i*PHTsize:PHToffset+(i+1)*PHTsize]
    TYPE = u32(PHTentry[:4])
    print('T:',TYPE)
    if TYPE!=1 and TYPE!=2:
        continue
    fileoffset = u64(PHTentry[0x8:0x10])
    virtualaddr = u64(PHTentry[0x10:0x18])
    sizeinfile = u64(PHTentry[0x20:0x28])
    print(hex(fileoffset),hex(virtualaddr),virtualaddr+sizeinfile,len(f))
    FILE.append((fileoffset,f[virtualaddr:virtualaddr+sizeinfile],sizeinfile))

FILE = sorted(FILE)
f = b''
for i in FILE:
    if len(f)<i[0]:
        f = f.ljust(i[0],b'\x00')
    print('BEF',len(f),i[0],i[2])
    f+=i[1]
    print('   ',len(f),i[0],i[2])
f2 = open('binaryfile','wb')
f2.write(f)
