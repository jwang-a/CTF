'''
Copied and modified from https://www.cnblogs.com/0x636a/p/9157993.html
All credits ro original author
'''
LD_PATH = ''

from pwn import *
import sys, os
def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.encode().ljust(size, b'\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                print("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    print("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)
#example
elf = change_ld('./john_cena', LD_PATH)
###Execute file by 'LD_PRELOAD={target_libc} ./executable'
