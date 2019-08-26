from pwn import *
###Padding in 32 bit might be broken, need further investigation


class Elf_Dyn(object):
    ###Under construction
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
    ###Under construction
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
            Elf_Addr r_offset;  //addr of got
            Elf_Word r_info;  //symbol index and relocation type; R_SYM=r_info>>32(8); R_TYPE=r_info&0xffffffff(0xff) 
        }Elf_Rel;
	
	R_TYPE
	    7 R_JMP_SLOT
        '''
        self.arch = arch
    def construct(self,r_offset=0,r_info=0):
        if self.arch==32:
            return p32(r_offset)+p32(r_info)
        elif self.arch==64:
            return p64(r_offset)+p64(r_info)+p64(0)

class Elf_Sym(object):
    def __init__(self,arch=64):
        '''
        typedef struct{
            Elf_Word st_name;	//offset to string table
            unsigned char st_info;	//symbol type and binding; ST_BIND=st_info>>4 ; ST_TYPE=st_info&0xf
            unsigned char st_other;	//symbol visibility; ST_VISIBILITY=st_other&0x3
            Elf_Section st_shndx;	//section index
            Elf_Addr st_value;	//symbol value if exported
            Elf_Word st_size;	//symbol size
        }Elf_Sym
        ST_BIND
            0 STB_LOCAL
            1 STB_GLOBAL
            2 STB_WEAK
            10 STB_LOOS
            12 STB_HIOS
            13 STB_LOPROC
            15 STB_HIPROC
        ST_TYPE
            0 STT_NOTYPE
            1 STT_OBJECT
            2 STT_FUNC
            3 STT_SECTION
            4 STT_FILE
            5 STT_COMMON
            6 STT_TLS
            10 STT_LOOS
            12 STT_HIOS
            13 STT_LOPROC
            15 STT_HIPROC
        ST_VISIBILITY
            0 STV_DEFAULT
            1 STV_INTERNAL
            2 STV_HIDDEN
            3 STV_PROTECTED
        '''
        self.arch = arch
    def construct(self,st_name=0,st_info=0,st_other=0,st_shndx=0,st_value=0,st_size=0):
        if self.arch==32:
            return p32(st_name)+p32(st_value)+p32(st_size)+p8(st_info)+p8(st_other)+p16(st_shndx)
        elif self.arch==64:
            return p32(st_name)+p8(st_info)+p8(st_other)+p16(st_shndx)+p64(st_value)+p64(st_size)

def Elf_Versym(object):
    def __init__(self,arch=64):
        '''
        int16 version
        
        reserved value:
            0 local symbol
            1 defined locally and global available
        '''
        self.arch=arch
    def construct(self,version):
        if self.arch==32:
            return p16(version)
        elif self.arch==64:
            return p16(version)

'''
r_debug
    |    4    |    4    |    4    |    4    |
0x00|r_version|    x    |   linkmap *rmap   |
0x10|      r_brk        |         x         |
0x20|    r_ld_base      |         x         |
'''


###Reference
#  https://code.woboq.org/userspace/glibc/elf/elf.h.html
#  http://refspecs.linuxbase.org/elf/gabi4+/ch4.reloc.html
#  http://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html
#  https://code.woboq.org/userspace/glibc/elf/link.h.html#r_debug
#  https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-di-frederico.pdf
#  https://lists.debian.org/lsb-spec/1999/12/msg00017.html
