import sys
import os
from pwn import *

def parsestr(data):
    return data[:data.find(b'\x00')]

def getSectionInfo64(data,section,info):
    if info=='sh_name':
        return u32(data[section:][:4])
    if info=='sh_type':
        return u32(data[section+0x4:][:4])
    if info=='sh_flags':
        return u64(data[section+0x8:][:8])
    if info=='sh_addr':
        return u64(data[section+0x10:][:8])
    if info=='sh_offset':
        return u64(data[section+0x18:][:8])
    if info=='sh_size':
        return u64(data[section+0x20:][:8])
    if info=='sh_link':
        return u32(data[section+0x28:][:4])
    if info=='sh_info':
        return u32(data[section+0x2c:][:4])
    if info=='sh_addralign':
        return u64(data[section+0x30:][:8])
    if info=='sh_entsize':
        return u64(data[section+0x38:][:8])

def searchShstrtab64(data):
    shdr64 = u64(data[0x28:0x30])
    shstrndx64 = u16(data[0x3e:0x40])
    return u64(data[shdr64+shstrndx64*0x40+0x18:][:8]), u64(data[shdr64+shstrndx64*0x40+0x20:][:8])

def searchNameIdx(data,strtab,strtab_size,name):
    if type(name)==type(''):
        name = name.encode()
    idx = 0
    while idx<strtab_size:
        cur = parsestr(data[strtab+idx:])
        if cur==name:
            return idx
        else:
            idx+=len(cur)+1
    return -1

def searchSection64(data,name):
    if type(name)==type(''):
        name = name.encode()
    shstrtab,shstrtab_size = searchShstrtab64(data)
    targetidx = searchNameIdx(data,shstrtab,shstrtab_size,name)
    shdr = u64(data[0x28:0x30])
    shdr_cnt = u16(data[0x3c:0x3e])
    for i in range(shdr_cnt):
        nameoff = getSectionInfo64(data,shdr+0x40*i,'sh_name')
        if nameoff==targetidx:
            return shdr+0x40*i
    return -1

def getSymbolInfo64(data,symbol,info):
    if info=='st_name':
        return u32(data[symbol:][:4])
    if info=='st_info':
        return data[symbol+0x4]
    if info=='st_other':
        return data[symbol+0x5]
    if info=='st_shndx':
        return u16(data[symbol+0x6:][:2])
    if info=='st_value':
        return u64(data[symbol+0x8:][:8])
    if info=='st_size':
        return u64(data[symbol+0x10:][:8])

def searchSymbol64(data,name):
    if type(name)==type(''):
        name = name.encode()
    strtab_hdr = searchSection64(data,b'.strtab')
    strtab = getSectionInfo64(data,strtab_hdr,'sh_offset')
    strtab_size = getSectionInfo64(data,strtab_hdr,'sh_size')
    targetidx = searchNameIdx(data,strtab,strtab_size,name)
    symtab_hdr = searchSection64(data,'.symtab')
    symtab = getSectionInfo64(data,symtab_hdr,'sh_offset')
    symtab_size = getSectionInfo64(data,symtab_hdr,'sh_size')
    symtab_entsize = getSectionInfo64(data,symtab_hdr,'sh_entsize')
    for i in range(symtab//symtab_entsize):
        nameoff = getSymbolInfo64(data,symtab+i*symtab_entsize,'st_name')
        if nameoff==targetidx:
            return symtab+i*symtab_entsize
    return -1

os.system(f'gcc -Wl,-z,lazy -fpie -fstack-protector-all -fno-builtin-printf {sys.argv[1]}.c -o {sys.argv[1]}')

with open(sys.argv[1],'rb') as f:
    data = f.read()
orig_fsize = len(data)

shdrcnt = u16(data[0x3c:][:2])
shstrtab,shstrtab_size = searchShstrtab64(data)

text_hdr = searchSection64(data,'.text')
text = getSectionInfo64(data,text_hdr,'sh_offset')
text_size = getSectionInfo64(data,text_hdr,'sh_size')

initarray_hdr = searchSection64(data,'.init_array')
initarray = getSectionInfo64(data,initarray_hdr,'sh_offset')
initarray_size = getSectionInfo64(data,initarray_hdr,'sh_size')

ehframe_hdr = searchSection64(data,'.eh_frame')
ehframe = getSectionInfo64(data,ehframe_hdr,'sh_offset')
ehframe_size= getSectionInfo64(data,ehframe_hdr,'sh_size')

modifier_sym = searchSymbol64(data,'modifier')
modifier = getSymbolInfo64(data,modifier_sym,'st_value')
modifier_size = getSymbolInfo64(data,modifier_sym,'st_size')

csuinit_sym = searchSymbol64(data,'__libc_csu_init')
csuinit = getSymbolInfo64(data,csuinit_sym,'st_value')
csuinit_size = getSymbolInfo64(data,csuinit_sym,'st_size')

data = data[:initarray_hdr+0x20]+p64(8)+data[initarray_hdr+0x28:]

shdrcnt+=1
data+=p32(getSectionInfo64(data,initarray_hdr,'sh_name'))+\
      p32(getSectionInfo64(data,initarray_hdr,'sh_type'))+\
      p64(getSectionInfo64(data,initarray_hdr,'sh_flags'))+\
      p64(getSectionInfo64(data,initarray_hdr,'sh_addr')+0x8)+\
      p64(getSectionInfo64(data,initarray_hdr,'sh_offset'))+\
      p64(8)+\
      p32(getSectionInfo64(data,initarray_hdr,'sh_link'))+\
      p32(getSectionInfo64(data,initarray_hdr,'sh_info'))+\
      p64(8)+\
      p64(getSectionInfo64(data,initarray_hdr,'sh_entsize'))

data = data[:ehframe]+b'\x00'*ehframe_size+data[ehframe+ehframe_size:]
REPEAT = (csuinit-modifier)//ehframe_size
REMAIN = (csuinit-modifier)%ehframe_size
'''
>>flag^2 is added to remove gdb artifact

https://github.com/bminor/binutils-gdb/gdb/elfread.c

if (!is_debuginfo_file (abfd)
	  && bfd_section_size (sect) > 0 && j == num_segments
	  && (bfd_section_flags (sect) & SEC_LOAD) != 0)
	warning (_("Loadable section \"%s\" outside of ELF segments\n  in %s"),
		 bfd_section_name (sect), bfd_get_filename (abfd));
'''
for i in range(REPEAT):
    shdrcnt+=1
    data+=p32(getSectionInfo64(data,text_hdr,'sh_name'))+\
          p32(getSectionInfo64(data,text_hdr,'sh_type'))+\
          p64(getSectionInfo64(data,text_hdr,'sh_flags')^2)+\
          p64(modifier+ehframe_size*i)+\
          p64(ehframe)+\
          p64(ehframe_size)+\
          p32(getSectionInfo64(data,text_hdr,'sh_link'))+\
          p32(getSectionInfo64(data,text_hdr,'sh_info'))+\
          p64(8)+\
          p64(0)
if REMAIN>0:
    shdrcnt+=1
    data+=p32(getSectionInfo64(data,text_hdr,'sh_name'))+\
          p32(getSectionInfo64(data,text_hdr,'sh_type'))+\
          p64(getSectionInfo64(data,text_hdr,'sh_flags')^2)+\
          p64(modifier+ehframe_size*REPEAT)+\
          p64(ehframe)+\
          p64(REMAIN)+\
          p32(getSectionInfo64(data,text_hdr,'sh_link'))+\
          p32(getSectionInfo64(data,text_hdr,'sh_info'))+\
          p64(8)+\
          p64(0)

data = data[:0x3c]+p16(shdrcnt)+data[0x3e:]
dataold = data

with open(sys.argv[1],'wb') as f:
    f.write(data)

os.system(f'strip {sys.argv[1]}')

with open(sys.argv[1],'rb') as f:
    data = f.read()

shdrcnt = u16(data[0x3c:][:2])

text_hdr = searchSection64(data,'.text')
text = getSectionInfo64(data,text_hdr,'sh_offset')
text_size = getSectionInfo64(data,text_hdr,'sh_size')

data = data[:text_hdr+0x20]+p64(data.find(dataold[modifier:modifier+modifier_size])-text)+data[text_hdr+0x28:]
data+=p32(getSectionInfo64(data,text_hdr,'sh_name'))+\
      p32(getSectionInfo64(data,text_hdr,'sh_type'))+\
      p64(getSectionInfo64(data,text_hdr,'sh_flags'))+\
      p64(csuinit)+\
      p64(data.find(dataold[csuinit:csuinit+csuinit_size]))+\
      p64(text_size-(data.find(dataold[csuinit:csuinit+csuinit_size])-text))+\
      p32(getSectionInfo64(data,text_hdr,'sh_link'))+\
      p32(getSectionInfo64(data,text_hdr,'sh_info'))+\
      p64(8)+\
      p64(0)
shdrcnt+=1
data = data[:0x3c]+p16(shdrcnt)+data[0x3e:]
with open(sys.argv[1],'wb') as f:
    f.write(data)
