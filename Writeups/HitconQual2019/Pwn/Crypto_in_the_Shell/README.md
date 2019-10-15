# Crypto in the Shell

## Index
[Index](#index)

[Problem Overcap](#problem-overcap)

[Exploit](#exploit)
	* [Vulnerability](#vulnerability)
	* [Control Key](#control-key)
	* [Address Leak](#leak-codebase-libcbase-and-stackaddr)
	* [Hijack flow](#bypass-encryption-rounds-limitation-hijack-flow)
	* [Handle Timeout](#handle-timeout) 

## Problem Overcap
The program provides a simple AES-CBC encrypt service, with the specification as below
1. padding is done by simply modifying plaintext length to multiples of 0x10
2. no user plaintext is taken, user can only provide offset to *buffer* and length
3. encryption is done inplace, and ciphertext will be printed
4. *key* is initialized from a 'key\_file', *iv* is initialized to 0, *buffer* is initialized to 0, all three located in .bss section
5. there is a integer counter in main function stack, when reaching 32, main returns

all protections are enabled

## Exploit

### Vulnerability
There is only one vulnerability in this program  
The program takes an offset to the *bufer*, and uses it to find where to encrypt, however, no check is performed on the offset, leading to possibility of out of bound access
Moreover, offset is a 64 bit value, meaning we can access anywhere inside as long as the code\_base and target\_address is known  
The only limitation is that since encryption is done inplace, only writeable sections are accessible  

### Control Key
Since it a legimate AES-CBC encryption, the first step to be able to interpret encrypted data is to leak key and iv

iv is known to be 0, so the only thing left it to leak key. The way to achieve this is to set offset to point to *&key* on bss, the program then encypts the key in place and outputs it. Though we still have no idea what the *original\_key* is, the program will use the encrypted *key* as future key from now on.

### Leak code\_base, libc\_base and stack\_addr
The next step is to leak code\_base and libc\_base and stack\_addr so we can leverage encryption mechanism to modify stack content and control flow

Let's look at libc\_base first. The most common way to leak libc\_base would be through reading .got table, however, as mentioned earlier that only writeable sections are accessible, .got is no an option. Luckily, there are still several pointers to libc in .bss section, which are stdin, stdout, stderr FILE struct pointer. Tampering stdin, stdout is out of question as it might break the process, but stderr is a fine target, so now we've got \_IO\_2\_1\_stderr\_ address and can calculated libc\_base with it

The next step is to leak code\_base, tracing the memory layout with gdb, and one can easily notice that at the very start of the .data section, there is a self referencing pointer, since .data is writeable, we can now leak code\_base

Finally, we have to know stack\_addr to be able to do anything interesting. Since code\_base and libc\_base is known, it is now possible to leak data inside libc, the \_environ symbol is perfect for our situation here. It contains a pointer to environ variable list located stack, and is always 0xf8 below rbp of main.

So now we have all the address we need, what next?

### Bypass encryption rounds limitation & Hijack flow
The next step is to devise a strategy to control program flow

The easiest way to do this is to construct a ROPchain at return address of main, since the only operation availabe is to provide plaintext offset and length, how is that even possible?

It turns out that the modern cryptography algorithms has a few good properties that come in handy. Modern crypto often requires output to 'seem random', this property allows us to make the assumption that for AES-CBC, the chance for first byte of ciphertext to be equal to a certain character C = $\frac{1}{256}$

How to write ROPchain onto stack is now clear : keep encrypting data in buffer until first byte is set to intended payload, move the buffer forward one byte and repeat process

Now the last limitation needed to be bypasses is limited rounds of encryption, the approach mentioned above takes about 128 rounds to set one byte, and a useful ROPchain contains at least 24 bytes, summing up to an expected 3072 rounds, taking into consideration that \_environ needs to be cleared for system("/bin/sh") to work, the required rounds would only increase.

The key here is to set counter on stack to a large negative value. This would allow close to unlimited rounds of encryption. Looking at the runtime stack, nothing within the 16 bytes after &counter needs to be preserved, so it is safe to encrypt it. Now directly setting offset to &counter and encrypting it has approximately 1/2 chance to succeed, which is good enough to blindly try it. But there is actually a way to ensure the exploit succeeds with about $\frac{2^{28}-1}{2^{28}}$ chance. As the 16 bytes after &counter is predictable, we can simulate the encryption locally and check if result satisfies our need. If not, encrypt IV to change the encryption result. Repeat this process several times and we are bound to hit the jackpot.

And don't forget to set counter back to some value>32 after finishing writing ROPchain to trigger return

### Handle Timeout 
So now we have changed counter, written ROPchain, everything done? The answer is no...

The network interaction speed is too slow for the encrypt -> get result -> check -> proceed algorithm. Connection simply timeout before we can write entire ROPchain. So how do we handle this?

Since the bottleneck lies in communication, if we can model the entire process locally and send payload at once, it can be bypassed. To do this, we first encrypt one first time with length=payload\_length+0x10 to get stack content. After getting stack content, it is now possible to carry out the entire byte by byte probing locally

Another problem sprouts after finishing implementing the local probing. The complete payload is too large to be sent in one shot. Apparently, output buffer of remote process fills up and the process will refuse to continue before we read output buffer. Handling this problem is quite easy, just break the payload into several chunks, send them one by one and read the remote process output in between. After some experiment, setting chunk size=10000 seems like a reasonable tradeoff point.



[Top](#crypto-in-the-shell)
