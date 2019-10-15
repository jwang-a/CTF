# One Punch Man

## Problem Overcap
This is a classic menu pwn problem, the allowed operations(with pseudo code describing what it does) is listed below

1. debut (create new chunk)
```
readint(idx)
if idx<0 or idx>3:
	exit()

clearbuf(data,0x400)
read(data,0x400)
if strlen(data)<0x80 or strlen(data)>0x400
	exit()

chunk_list[idx]->buffer = calloc(strlen(data))
strncpy(global_chunk_list[idx*2],data,strlen(data))
chunk_list[idx]->size = strlen(data)
clearbuf(data)
```

2. rename (edit chunk)
```
readint(idx)
if idx<0 or idx>3:
	exit()

if chunk_list[idx]->buffer = NULL
	exit()

read(chunk_list[idx]->buffer,chunk_list[idx]->size)
```

3. show
```
readint(idx)
if idx<0 or idx>3:
	exit()

if chunk_list[idx]->buffer != NULL
	puts(chunk_list[idx]->buffer)
```

4. retire (delete chunk)
```
readint(idx)
if idx<0 or idx>3:
	exit()

free(chunk_list[idx])
```

5. exit (do nothing)
```
continue
```

6. serious_punch (create with malloc)
```
if tcache->counts[size2idx(0x217)]<7:
	exit()

special = malloc(0x217)
read(special,0x217)
puts(special)
```

additionally, the program uses glibc2.29, and applies seccomp which allow only the syscalls listed below  
open, read, write, brk, mmap, mprotect, sigreturn, exit, exitgroup

all protections are enabled

## Exploit

### Vulnerability
Before going on, lets review some basic knowledge about tcache and calloc  
1. Tcache in glibc2.29 enables a checking mechanism that prevents double-frees, how it works is not important here, so I'll just skip it  
2. Calloc does **not** take chunks from tcache. It allocates from the usual arena bins, but freed chunks will still result going to tcache  

It is immediate that retire has a use after free, buf since it neither clears pointer or size after freeing chunk. This bug can be upgraded into a heap buffer overflow if we can create a chunk -> free it into unsorted -> create a smaller chunk

That's pretty much all there is about the vulnerability, so let's start looking at how this vulnerability can be exploited

### Challenges
There are 3 main difficulties in the problem
1. calloc takes chunk only from usual bins, but is limited to size>=0x80, this means normal fast-bins attacks are rendered completely useless it overwriting libc content
2. The only malloc is serious punch requires tcache to be full, this means that we even if we managed to hijack the tcache chunk linked list, it would be useless since the hijacked pointer can never be extracted. Only by directly editing tcache entry can we have an arbitrary malloc
3. Seccomp is enabled so simply hijacking a hook will not be enough, we need a ROPchain to perform open -> read -> write to get flag

Now lets see how we tackle those difficulties  

### Leak libc\_base and heap\_addr
This part is relatively easy, since we have a use\_after\_free, and the programs allows showing data on heap, we can repeatedly creating chunks and freeing them, since those chunks are created with calloc, the tcache will be flooded, and we will eventually get a chunk that falls in unsorted\_bin. Showing those chunks leak the tcache linked list (where we can obtain heap\_address) and unsorted\_bin address..


### Creating overlap chunk with tcache
Since an arbitrary malloc is necessary(even for just hijacking hooks), we must somehow find a way to edit the tcache struct at front of heap. The most straightforward way to do this is to manage to calloc a chunk onto tcache, but since calloc only mallocs from normal bins, we must first create a free chunk on tcache, and have it's field set to acceptable value, but how is that even possible?  

Lets first lay out the tcache structure as below  
```
     |       8       |       8       |
0x000|     unused    |            251|
0x010|               |               | <- counts for size 0x20  ~ 0x110
0x020|               |               | <- counts for size 0x120 ~ 0x210
0x030|               |               | <- counts for size 0x220 ~ 0x310
0x040|               |               | <- counts for size 0x320 ~ 0x410
0x050| entry_for_0x20| entry_for_0x30|
 					...
```

It isn't hard to see that at heap+0x40, we can possible craft a fake chunk that has valid header, by doing the things listed below
* free(0x20)
* free(0x30)
* free(0x3a0)
* free(0x3b0)*3

Notice that since we never had a chance to create chunk of size 0x20 or 0x30, crafting those chunks must be done by utilizing buffer overflow bug mentioned in Vulnerability section.

The result should be like
```
     |       8       |       8       |
                    ...
0x040|               |            301| <- tcache_fake_chunk
0x050| ptr2freed_0x20| ptr2freed_0x30|
```

Now we have something that looks like an unsorted chunk on tcache, if we manage to perform a unlink on it, we will get a free chunk that overlaps with tcache. Actually, this is the very reason why I chose to free(0x3b0) 3 times, by doing so, we manage to set the next chunk to heap+0x340, which is at about the start of usable heap region.

So we now have to try to perfrom unlink on that chunk, to do so, we must utilize the buffer overflow bug mentioned in Vulnerability section. The procedure can be outlined as this
1. C1 = create(0x388)					# size chosen to be sum of tcache\_fake\_chunk and next\_chunk
2. (C2 = create(0x388),delete(C2))*7	# flood tcache to let freed C1 end up in unsorted bin
3. (C2 = create(0x88),delete(C2))*7		# flood tcache for 0x90, so the crafted next\_chunk can be freed into unsorted bin and trigger unlink
4. delete(C1)
5. C2 = create(0xe8)					# padding the next chunk into heap+0x340
6. C2 = create(0xf8)					# the chunk that will be modified to next\_chunk of tcache\_fake\_chunk
7. C3 = create(0x88)					# just for exausting unsorted being at current point, usage will be explored later
8. edit(C1, padding+fakeC2chunk(size=0x90, prev\_inuse=False, prev\_size=0x300, next\_chunk is valid))	# craft next\_chunk for tcache\_fake\_chunk
9. delete(C2)


The heap before finally freeing C2 to trigger unlink should look something like this
```
     |       8       |       8       |
0x250|     unused    |             f1|
                    ...
0x340|            300|             90| <- C2
                    ...
0x3d0|               |             71| <- next chunk for C2, so that freeing C2 will not trigger any error
                    ...
0x440|               |             91| <- C3
```


### Putting it together
Now we have managed to leak libc\_base, leak heap\_addr ,craft tcache\_fake\_chunk and craft next\_chunk to unlink with it seperately, lets see how we can combine those two parts to actually trigger unlink without getting any errors

The entire procedure can be illustrated as below, notice the difference between this and previous listed procedure
1. C1 = create(0x388)
2. C2 = create(0x388)					# for leaking heap
3. C3 = create(0x388)					# for leaking heap
4. delete(C2)
5. delete(C3)
6. show(C3)								# leak heap
7. (C2 = create(0x398), delete(C2))		# set tcache\_fake\_chunk -> prev\_inuse = 1
8. (C2 = delete(0x3a8), delete(C2))*3	# set tcache\_fake\_chunk -> size = 0x300
9. (C2 = create(0x388),delete(C2))*5	# two were freed earlier, only five more needed
10. (C2 = create(0x88),delete(C2))*7
11. delete(C1)							# leak unsorted bin
12. C2 = create(0xe8)
13. C2 = create(0xf8)
14. C3 = create(0x88)
15. edit(C1, padding+fakeC3chunk(size=0x21, prev\_inuse=True, next\_chunk is valid))	# craft 0x20 chunk
16. delete(C3)																			# set tcache\_fake\_chunk -> fd = C3+0x10
17. edit(C1, padding+fakeC3chunk(size=0x31, prev\_inuse=True, next\_chunk is valid))	# craft 0x30 chunk
18. delete(C3)																			# set tcache\_fake\_chunk -> bk = C3+0x10
19. edit(C1, padding+fakeC2chunk(size=0x90, prev\_inuse=False, prev\_size=0x300, next\_chunk is valid)+fakeunsortedchunk(addr=C3+0x10))
20. delete(C2)

Most of the difference are trivially understandable, the only step that probably needs some explanation is #19  
The fake\_unsorted\_chunk in this need not be a legimate chunk, it is assigned to satisfy the needs for unlinking properly  

As we all know the only check in unlink is  
```
if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
	malloc_printerr ("corrupted double-linked list");
```
So to unlink properly, we have to set
1. tcache\_fake\_chunk -> fd -> bk = tcache\_fake\_chunk
2. tcache\_fake\_chunk -> bk -> fd = tcache\_fake\_chunk

Since both fd, bk of tcache\_fake\_chunk = C3+0x10  
fd, bk of C3+0x10 must be set to tcache\_fake\_chunk



Here is what the heap will look like before finally freeing C2 to trigger unlink
```
     |       8       |       8       |
                    ...
0x040|               |            301|
0x050|   heap+0x450  |   heap+0x450  | <- tcache_fake_chunk
                    ...
0x250|               |             f1|
                    ...
0x340|            300|             90| <- C2
                    ...
0x3d0|               |             71| <- next chunk for C2, so that freeing C2 will not trigger any error
                    ...
0x440|               |             91| <- C3
0x450|               |               | <- fake_unsorted_chunk
0x460|   heap+0x40   |   heap+0x40   |
```

after freeing, we will finally have the tcache\_fake\_chunk placed in unsorted bin  
At this point we can edit tcache entry for 0x220 easily

### Deal with Seccomp
So we have the ability to malloc to arbitrary position, or maybe not?  

Turn out that we forgot to flood up tcache count for 0x220, but this can be easily done by adding some create and delete between step 7 and step 8  

To bypass seccomp, we have to write a ROPchain, and that would most definitely be on stack, so now the next step is to leak stack\_addr. Luckily, with arbitrary malloc, we can just create a chunk at &_environ and leak stack address. After getting the stack address, we have to create another chunk on stack, but hey, isn't tcache count for 0x220 lowered to 6 again? What should we do? The cure is simple, since unsorted bin is now empty, we can safely create 0x220 chunks from heap\_top through calloc without causing any trouble, free them to refill tcache, and edit tcache to get arbitrary free pointer again. So now we can write out ROPchain onto stack.  

Another trivial problem here is main never returns, but we can overwrite return address of serious\_punch anyway...

And just some small tips, writing syscalls in ROPchain is a hassle, so why not just create ROPchain thats calls mprotect to make .bss executable, write shellcode in .bss and jump to it? This would certainly make life easier

### Where to find flag?
One last thing, with only open/read/write, how should I know where the flag is?  

The author is kind enough to make path to the program reasonable (/home/ctf/flag), but I was too dumb to guess it. One thing I know is that conventionally, flags are placed in files named 'flag' or 'flag.txt', and usually resides in either root dir or in the same dir as program.

So I decided to read /proc/self/maps to leak the path to executable, and finally got the flag
