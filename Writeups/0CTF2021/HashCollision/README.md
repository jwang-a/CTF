# (Hash) Collision

## Index
*   [Index](#index)

*   [Recap](#recap)

*   [Exploit](#exploit)
    *   [Utilize OOB](#utilize-oob)
    *   [Hash Collision](#colliding-hash)
    *   [Chaining it all (Painful Stuff)](#chaining-it-all)

*   [Fun Fact](#fun-fact)


## Recap

This challenge implements a random hash collision game.

The basic program flow is as follow:
1. set srand(time(0)), apply seccomp to filter execve syscall, malloc a bunch of heap chunks
2. mmap a page of size 0x2000 (address generated with rand(), but MAP\_FIXED flag is not set)
3. generate a batch of 0x400 random numbers, and store each into a 0x20 sized heap chunk, ptrs to those heap chunks are stored in mmap page
4. allow user to provide arbitrary data, hash the data with custom algorithm, then compare with selected random number
5. if compare succeeds, free random number chunk and NULL out ptr in mmap page
6. if compare fails, the fail will be counted, >3 fails will trigger a puts(GAME\_OVER\_MSG) and exit
7. upon gussing all 0x400 numbers, restart from (2), if cleared 0x100 batches of number, trigger puts(WIN\_MSG) and exit

Two parts worth mentioning are
1. index check when selecting random num to guess is not complete, index can be negative, but limited to 7 bytes decimal numbers
2. no modification of stdin/stdout buffering mode are done


All protections are enabled

## Exploit

Overall, the exploit can be split into two parts:
1. come up with a reliable way for hash collision
2. utilize OOB to pwn binary

Since the two parts are somewhat independent, I'll introduce them in the order I solved it. pwn -> collision.

### Utilize OOB
Before pwning stuff, I usually check dependencies and set them up to be similar to remote environment, This is of utmost importance as developing a local working exploit that fails on remote is somewhat frustrating.

For cases where Dockerfile is not provided (or I'm too lazy to set up docker), I usually make things work with this workflow
1. check library versions and download matching linker
2. patch binary to use the specific linker
3. LD\_PRELOAD all libs

This works for 90% of cases, but is going to cause some problems for this specific challenge, I'll discuss it as we proceed through the solving progress

By inspecting the binary, there is no leak at first glance, and while the mapped page addresses are predictable, and we can reference a previous mapped page with negative OOB, it is kind of useless since by the time we reference it, the page will be all NULLED out.

So the first step of exploting is to find the breakthrough point. 

As mentioned in the recap part, mapped address are chosen at random, this might ring a bell with people familiar with mmap bugs in previous CTFs. Multiple challenges in the past that utilized mmap address overlap + MAP\_FIXED to overwrite original content, and while we don't have MAP\_FIXED flag here, this actually introduces a different affect.

When MAP\_FIXED flag is set, the page is forced to mmap to assigned address, meaning guaranteed overlapping with original page, the exact behaviour is original page is unmapped, then new page is mapped in place. This pattern creates a chance of unintendedly overwriting existing content.

On the other hand, when MAP\_FIXED is not set, the behaviour is slightly more complex, quoting from the man page :

> If addr is not NULL, then the kernel takes it as a hint about where to place the mapping; on Linux, the kernel will pick a nearby page boundary (but always above or equal to the value specified by /proc/sys/vm/mmap\_min\_addr) and attempt to create the mapping there.  If another mapping already exists there, the kernel picks a new address that may or may not depend on the hint.

So if there is a collision for the randomized map address, there is a certain chance that second attempt for nearby address also fails, and the mmap will completely ignore addr. This is exactly what I want, a free mmap that is default placed at some fixed offset to libc. Coupled with the negative index OOB, we can reference pointers in libc without an actual leak.

Now comming up with the idea is one thing, and doing it is another, so I quickly patched the challenge binary to make rand() and hash() both return a fixed value (heavylift the need to do hash collision/wait for overlapping addres), and tried running the program.

It worked! But quite not as expected. The mapped page comes before libc, which is kind of troublesome given that we have only negative OOB. A intuitive approach for these cases is to try overflowing the actual offset (offset = index\*8), but the program reads at most 7 bytes of decimal digits, making this impossible. At this point I was stuck, and decided to work on some other challenges.

After solving a few other pwns, and coming back about 6 hours later, I noticed that the author released the Dockerfile. Still too lazy to set it up, I reexamined the memory mapping and noticed something interesting, the ordering of libseccomp & libc is different from ldd result. This reminded me of previous experience of caluculating wrong tls offset due to LD\_PRELOAD, so I quickly switched from LD\_PRELOAD to LD\_LIBRARY\_PATH and presto! mmap page now comes after libc. Time to continue exploiting.

So I now can free arbitrary pointer in libc, what next? Leak, of course, leak everytime.

A common way to leak without printing from user provided pointers is playing with stdout file stream. So I first tried freeing stdout buffer, and was presented with a one byte leak following output message "unbelievable\n".

To understand what is happening under the hood, we must gain further insight about glibc stdout mechanisms. There are a total of 3 types of buffering mode for file stream, FULL\_BUF, LINE\_BUF, and NO\_BUF. By default, stream with a tty attached will have LINE\_BUF, and most pwn challenges set buffering to NO\_BUF to prevent IO synchronization issues.

Process run by pwntools has stdout backed by tty, so my setup uses LINE\_BUF. This means every newline printed will trigger a stdout buffer flush. The success message for colliding a hash with random number is "unbelievable\n", 13 bytes in total. By freeing stdout buffer, at most two pointers are written to stdout buffer, and the two most significant bytes of a pointer is always '\x00', so 13 out of the 16 potential pointer byte leaks are overwritten, and the 2 MSB are useless, this creates the 1 byte leak scenario we saw.

So no leaks possible, think about the remote setup. The program is actually ran by xinetd, which functions as a daemon, and won't have tty backed stdout. This mean in actual target environment, the buffer pointer will not be reset to start of buffer whenever a message is printed, and the leaked pointer might not be overwritten if we carefully manage how many bytes are stored in buffer at time of free. This is the second time environment setup got me for this challenge, time to set up docker.

After launching docker, we have to deal with IO synchronization while sending messages (output will only come back when stdout buffer is completely filled), but leaking is now possible. After getting libc/heap leak, it's time for further utilize the bug for something other than leak.

As of libc2.31 (version used in this binary), tcache double free is guarded by the key field, but since we can repeatedly write the success message onto stdout buffer, this check is bypassible by overwriting key. And utilizing the fact that stdout refills the freed and nulled out fp->\_IO\_read\_ptr, we can easily get double free to stdout buffer.

From double free stdout to arbitrary write is also quite trivial, but the question is what to overwrite? Seccomp is enabled so we can't directly call system and get shell, what we can do is try to perform a stack pivot and get ROP. I managed to do this by
1. malloc a chunk to overwrite tcache struct and create two fake chunks pointing to stdout and malloc hook
2. overwrite stdout vtable to point to IO\_str\_jumps-0x20, this transforms any call for \_IO\_new\_file\_xsputn into \_IO\_str\_overflow, which then calls malloc with rdx set to fd->\_IO\_write\_ptr
3. overwrite \_\_malloc\_hook with setcontext gadget, which set rsp by dereferencing from struct pointed by rdx

After setting up stuff, trigger stack pivot with puts(), ROP to mprotect some page, and run shellcode to call execveat("ls") for flag filename leak and execveat("cat"), The reason getting a shell with execveat("/bin/sh") won't work is /bin/sh runs other commands with execve, which is blocked by seccomp.

### Colliding Hash

As a pwn guy, I generally avoid doing mathy stuff in CTFs. Not that I hate it, but letting crypto guys solve them is far more time efficient. However, as most of my teammates are either busy with work or doing their master thesis this year, I am the only person tryharding this CTF. After announcing solving the pwn part, and leaving to solve doing some other challenges, it seems like it's either solve it myself or leave it unsolved. Ok, challenge accepted.

Analyzing the hash function, we can first divide it into two parts:
1. deterministic key table generation with 256 integer entries (only done once)
2. mix input with key

Since key table is fixed, we can just dump the value from runtime, no point looking into generation algorithm.

The mix input part is shown below(R is key)
```
def forwardpass(data):
    v7 = 0
    v9 = 0
    for i in range(len(data)):
        v10 = data[i]
        v11 = (v7^v9^v10)&0xff
        v7 = v10&0xf0
        v9 = R[v11]^(v9>>8)
    return v7, v9


def mix(data):
    v7, v9 = forwardpass(data)
    v4 = v9>>8
    v5 = (v7^v9)&0xff
    v12 = R[v5]^v4
    v13 = R[v12>>24]
    v14 = R[(v13^(v12>>8))&0xff]^(v13>>8)
    v15 = R[(v14^v12)&0xff]^(v14>>8)
    return 0xffffffff^(R[(v15^(v12>>16))&0xff]^(v15>>8))
```

My first intuitive is that not all hash are producible, which is kinda strange since to reach the pwn part, we essentially have to collide a few thousands hashes with random values, so this intuitive should be wrong, but how...

Clearly, staring at the algorithm doesn't help much, so let's start decompositing the hash. For a hash result to exist, there must be some R where 

```
0xff^(R[x]>>24)==target>>24 
```

Checking with the keys, suprisingly I found that each bytes from 0~0xff appears only once in R[x]>>24!

This means that we can deduce a unique v15^(v12)>>16 from the hash result, which also means we can retrieve a unique v15>>8

Using similar techniques, we can inverse the hash all the way to v12.

Combining with the limitation where all input is terminated by NULL(technically not 100% correct, but we'll settle with this), we have v7 in mix==0, so v9 is also calculatable, now we only have forwardpass() to deal with.

forwardpass() adopts a structure where the v7 only depends on last input, and the last byte of v9 is consistently shifted out (while last byte of v9 is xored to produce v11, both v7/v9 are semi-controllable with input, so it's affect can most likely neglected) 

This means that inputs other than the last 4 bytes have diminishing contribution to hash result, and generating hash collision will be highly possible.

The primitive I would need for exploit is

```
given prefix, length where len(prefix)\<length-8
find padding, suffix where len(suffix)==4 and len(prefix+padding+suffix)==length and suffix[-1]=0 that satifies target\_hash
```

The graph below provides an intuitive explanation of collision algorithm, X is state after processing prefix+padding, R is target output

```
            X  X  X  X
         U1 U1 U1 U1
      U2 U2 U2 U2
   U3 U3 U3 U3
U4 U4 U4 U4
R  R  R  R
```

Given v7 and v9 at the end of forwardpass(), we can directly compute the last 4 v11(key table entries) required to generate hash, and from v11 and current state, we can get the last 4 v10(input) that can produce those desired v11. By comparing whether the last v10==0, we can conclude whether the provided prefix+padding is collidable. 

Since there is a 1/256 chance of succeed (idk if key values affect this, but empirical results show success rate is quite high), just randomly regenerate padding until a solution is found.

### Chaining it all

Hash collision + Pwn = flag? Not so fast.

We have still yet to actually chain it all together and get it working. Now the key is to get some timestamp where mmap address collides whithin a few regen of rand value batches, and this proves to be truly a hassle.

One could obviously try & reconnect to server whenever the previous attempt timeout, but since good timestamps are rare, this approach would risk missing those honeyspots during trying to solve some hopeless timestamp.

Another issue is that those unsolved connections will live up to 30 seconds (later reset to 300 seconds) until timeout. And the remote docker xinetd would soon be flooded with connections and start mulfunctioning. In fact, this is the very first problem we met when trying our exploit on remote. Someone is bruteforcing the service, and my connection keep getting reset. (Full disclosure, I was lazy and also did some bruteforce at the very start, but too ashamed to tell author about this 0^0)

Thankfully, the author was very generous and launched another instance when I contacted his about the ongoing bruteforce (love you for this). And by the time the second instance is up, we have already modified our script to locally search for good timestamps and only connect on those timestamps. Sadly this still didn't work. We are not getting any leaks when we are expecting it.

After banging my head against my pillow (not the wall) for a few 20 minutes, I realized that during exploit development, I installed gdb in my docker image, which potentially messed up the mapped page to libc offset (third time environment setup got me). After fixing this, and handing the exploit to my teammate who has a better processor for hash collision generation, we finally got flag on remote 3.5 hours after local solve.

Kudos to ripples for such an amazing challenge, and no fret, I still had fun despite the painful remote exploit procedure.

## Fun fact

1. The challenge was renamed at some point from "Hash Collsion" to "Collision". On retrospect, this change is intended to hint towards the collision of mmap address. But since I have already wrote exploit for that part, it was kind not at all helpful...
2. After discussing with author after solving challenge, me mentioned directly overwriting \_\_free\_hook with a trampoline gadget is enough to get stack pivot. While I have the trampoline gadget included in exploit, it is not used anywhere... I wonder what kept me from writing \_\_free\_hook at time of exploit development
3. The file exploit technique is used in one of my challenges for Balsn ctf last year, sadly no one solved it. The challenge will be republished in this year's Balsn ctf under homework category [1], interested players are encouraged to spend time solving it before CTF starts
4. If you enjoy mmap related stuff, you'll probably enjoy playing my Balsn ctf challenge this year >.0

## 
[1] See our twitter for more information about the new homework category [link](https://twitter.com/balsnctf/status/1407656712778125319?s=20)

[Top](#hash-collision)
