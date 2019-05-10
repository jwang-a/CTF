from pwn import *
###Padding in 32 bit might be broken, need further investigation


class Elf_Dyn(object):
    def __init__(self,arch=64):
        '''
        typedef struct{
            Elf_Sword d_tag;
            union{
                Elf_Word d_val;
                Elf_Addr d_ptr;
            } d_un;
        }Elf_Dyn;
        '''
        self.arch = arch
    def construct(self,d_tag=0,d_val=0,d_ptr=0):
        if d_val!=0 and d_ptr!=0:
            raise Exception('ArgumentsExceeded','d_val/d_ptr cannot exist at the same time')
        d_un = d_val+d_ptr
        if self.arch==32:
            return p32(d_tag)+p32(0)+p32(d_un)+p32(0)
        elif self.arch==64:
            return p64(d_tag)+p64(d_un)

class Elf_Shdr(object):
    def __init__(self,arch=64):
        '''
        typedef struct{
            Elf_Word sh_name;
            Elf_Word sh_type;
            Elf_Word sh_flags;
            Elf_Word sh_addr;
            Elf_Word sh_offset;
            Elf_Word sh_size;
            Elf_Word sh_link;
            Elf_Word sh_info;
            Elf_Word sh_addralign;
            Elf_Word sh_entsize;
        }Elf_Shdr;
        '''
        self.arch = arch
    def construct(self,sh_name=0,sh_type=0,sh_flags=0,sh_addr=0,sh_offset=0,sh_size=0,sh_link=0,sh_info=0,sh_addralign=0,sh_entsize=0):
        if self.arch==32:
            return p32(sh_name)+p32(sh_type)+p32(sh_flags)+p32(0)+p32(sh_addr)+p32(0)+p32(sh_offset)+p32(0)+p32(sh_size)+p32(0)+p32(sh_link)+p32(sh_info)+p32(sh_addralign)+p32(0)+p32(sh_entsize)+p32(0)
        elif self.arch==64:
            return p32(sh_name)+p32(sh_type)+p64(sh_flags)+p64(sh_addr)+p64(sh_offset)+p64(sh_size)+p32(sh_link)+p32(sh_info)+p64(sh_addralign)+p64(sh_entsize)

class Elf_Rel(object):
    def __init__(self,arch=64):
        '''
        typedef struct{
            Elf_Addr r_offset;
            Elf_Word r_info;
        }Elf_Dyn;
        '''
        self.arch = arch
    def construct(self,r_offset=0,r_info=0):
        if self.arch==32:
            return p32(r_offset)+p32(r_info)
        elif self.arch==64:
            return p64(r_offset)+p64(r_info)

class Elf_Sym(object):
    def __init__(self,arch=64):
        '''
        typedef struct{
            Elf_Word st_name;
            unsigned char st_info;
            unsigned char st_other;
            Elf_Section st_shndx;
            Elf_Addr st_value;
            Elf_Word st_size;
        }Elf_Sym
        '''
        self.arch = arch
    def construct(self,st_name=0,st_info=0,st_other=0,st_shndx=0,st_value=0,st_size=0):
        if self.arch==32:
            return p32(st_name)+p8(st_info)+p8(st_other)+p16(st_shndx)+p32(st_value)+p32(0)+p32(st_size)+p32(0)
        elif self.arch==64:
            return p32(st_name)+p8(st_info)+p8(st_other)+p16(st_shndx)+p64(st_value)+p64(st_size)


###Reference
#  https://code.woboq.org/userspace/glibc/elf/elf.h.html
