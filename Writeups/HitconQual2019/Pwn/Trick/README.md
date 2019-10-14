# Trick or Treat

## Problem Overcap
The binary is rather simple. The basic program flow can be concluded as below

```
    Addr = malloc(arbitrary_size)
    printf("%p",Addr)

    for i in range(2):
        write(...)
        scanf("%lx %lx",&pos,&dat)
        *pos = data

    _exit()
```

All protections are enabled

##Exploit

### Libc leak
There is a well known technique that by allocating a buffer large enough, it will end up being aligned right in front of glibc, this allows us to leak glibc address with the first printf.

We can also choose to malloc a not-so-large buffer to have it end up in front of ld, but since \_exit() is called here, there is no chance of hijacking atexit() functions, so this option is not really a choice


### First attempt
Now we have libc\_base, the problem is where to write?  
It is common to hijack hooks, namely malloc\_hook, free\_hook and realloc\_hook  

So my first attempt is to overwrite malloc\_hook with one\_gadget and trigger malloc by sending in a large enough payload in the second scanf  

So far, the exploit looks fine, and works locally on my machine with glibc2.29, so case closed? Actually no...  

It turns out that the remote version of glibc2.27 does not have same gadget that requires [rsp+0x60]=NULL, but have one that requires [rsp+0x70]=NULL instead  

This small difference completely spoils the entire exploit  

I also tried hijacking free\_hook and realloc\_hook, and with other available one\_gadgets, but after testing all combinations, none of them work on the remote server.  

### Second attempt
Okay, so how about hijacking free\_hook with system(), and sending argument in second payload?  

This approach seems promising, but I soon faced the problem where "%lx" takes only hexadecimal digits [0-9,a-f], and as far as I know, there are no commands consisting of just these 16 characters and is able to spawn a shell. (It was only after reading other's writeup did I realize that we can actually call system("ed"); and pass "!sh" to it to get shell)  

Since hijacking those hooks failed, I decided to dive deeper into scanf source code and try to figure out how to trigger malloc/free while allowing me to sneak in "/bin/sh", the attempt failed, but allowed me to gain enough knowledge and pwn the problem using the inner mechanisms of scanf()  

### Final Exploit
I wiil just explain the concept here, related code snippets from glibc can be found in appendix

Since the problem with the original one\_gadget approach sprouts from different stack layout, if I can probe the stack up and down for a bit, there is a high chance that the exploit will now succeed  

So how is this even possible? Well, if I can overwrite malloc\_hook to point to realloc, then overwrite realloc\_hook to point to one\_gadget, the additional function call will push stack upward, successfully probing it  

Now the target is simplified to overwrite malloc\_hook and realloc\_hook before calling malloc ,but once again, the problem only allows one modification before calling the last scanf, so I can't overwrite both hook directly 

The key point lies in that if I modify stdin IO\_FILE structure, I can forge stdin->buf\_base to point to start to stdin\_struct, upon the second scanf, the data is directly read from the start of the stdin\_struct until stdin->buf\_end, this allows a full hijack of the stdin struct  

On the second scanf, I first need to prepare to modify stdin->buf\_end to after malloc\_hook, so i can hijack it with subsequent input data  
The idea is to set stdin values as below : 
* read\_ptr = original\_buf\_base 
* read\_end = original\_buf\_base-readsize
* read\_base = &stdin\_struct
* read\_end = malloc\_hook+0x8
* \*original\_buf\_base value = 'a'

Assigning read\_ptr, read\_end and \*original\_buf\_base allows tricking inchar() into believing that I have not given any invalid input  

Setting read\_base and read\_end allows next hijack to overwrite realloc\_hook and malloc\_hook  

The following payload sets values as : 
* restore stdin\_struct to original value
* read\_end = original\_buf\_base=readsize
* malloc\_hook = &realloc
* realloc\_hook = &one\_gadget
* be sure to not modify anything in between, don't want unexpected errors popping up

Again, inchar() will be tricked into believing there is no invalid input

The subsequent payload just needs to trigger malloc from libc_scratch_buffer_grow_preserve(), and done? No...

It appears that simply calling realloc() before one\_gadget does not nudge stack into a favorable position, so I observed a little and noticed the first few instructions of realloc() are a series of push, by skipping just the first push, the stack is fixed and exploit will work


## Appendix
1. scanf() source code (https://code.woboq.org/userspace/glibc/stdio-common/scanf.c.html)
2. vfscanf() source code (https://code.woboq.org/userspace/glibc/stdio-common/vfscanf-internal.c.html)
3. scratch\_buffer\ struct source code (https://code.woboq.org/userspace/glibc/include/scratch\_buffer.h.html)
4. scratch\_buffer\_grow\_preserve() source code (https://code.woboq.org/userspace/glibc/include/scratch\_buffer.h.html)
5. IO\_getc\_unlocked() source code (http://code.skysider.top:2227/public\_html/glibc/glibc/libio/bits/libio.h.html)
6. \_\_uflow() source code (https://code.woboq.org/userspace/glibc/libio/genops.c.html)
7. \_IO\_default\_uflow source code (https://code.woboq.org/userspace/glibc/libio/genops.c.html)


**scanf**
```
int __scanf (const char *format, ...){
	...
	done = __vfscanf_internal (stdin, format, arg, 0);
	...
	return done;
}
```
**vfscanf_internal**
```
int __vfscanf_internal (FILE *s, const char *format, va_list argptr, unsigned int mode_flags){
	*f = format;
	...
	ARGCHECK (s, format);		// if(s->flag & _IO_NO_READS || format==NULL) exit(-1);
	...
	while (*f != '\0'){
		...
		fc = *f++;
		if (fc != '%'){...}		// non format string must just match
		...
		switch(*f++){			/* Check for type modifiers.  */
			...
			case L_('l'):
				if (*f == L_('l')){		/* A double `l' is equivalent to an `L'.  */
					++f;
					flags |= LONGDBL | LONG;
				}
				else					/* ints are long ints.  */
					flags |= LONG;
				break;
			...
		}
		...
		fc = *f++;
		...
		switch(*f++){
			...
			case L_('x'):        /* Hexadecimal integer.  */
			case L_('X'):        /* Ditto.  */
				base = 16;
				goto number;
			...
			number:
				c = inchar ();
				...
				if (base==10){
					...
				}
				else			/* Read the number into workspace.  */
					while (c != EOF && width != 0){
               			if (base == 16){
							if (!ISXDIGIT (c))		// Check if char is valid
								break;
						}
               			else if (!ISDIGIT (c) || (int) (c - L_('0')) >= base){	//
							...
						}
						char_buffer_add (&charbuf, c);
						if (width > 0)
							--width;
						c = inchar ();
					}
				...
			...
		}
		...
	}
	...
	scratch_buffer_free (&charbuf.scratch);
	...
	return done;
}	
```
**scratch_buffer structure**
```
struct scratch_buffer {
	void *data;    /* Pointer to the beginning of the scratch area.  */
	size_t length; /* Allocated space at the data pointer, in bytes.  */
	union { max_align_t __align; char __c[1024]; } __space;
};
```
**char_buffer_add**
```
void char_buffer_add (struct char_buffer *buffer, CHAR_T ch){
	if (__glibc_unlikely (buffer->current == buffer->end))
		char_buffer_add_slow (buffer, ch);
	else
		*buffer->current++ = ch;
}
```
**char_buffer_add_slow**
```
void char_buffer_add_slow (struct char_buffer *buffer, CHAR_T ch){
	if (char_buffer_error (buffer))
		return;
	size_t offset = buffer->end - (CHAR_T *) buffer->scratch.data;
	if (!scratch_buffer_grow_preserve (&buffer->scratch)){
		buffer->current = NULL;
		buffer->end = NULL;
		return;
	}
	char_buffer_rewind (buffer);
	buffer->current += offset;
	*buffer->current++ = ch;
}
```
**scratch_buffer_grow_preserve**
```
static __always_inline bool scratch_buffer_grow_preserve (struct scratch_buffer *buffer){
	return __glibc_likely (__libc_scratch_buffer_grow_preserve (buffer));
}
```
**libc_scratch_buffer_grow_preserve**
```
bool __libc_scratch_buffer_grow_preserve (struct scratch_buffer *buffer){
	size_t new_length = 2 * buffer->length;
	void *new_ptr;
	if (buffer->data == buffer->__space.__c){
		/* Move buffer to the heap.  No overflow is possible because
			buffer->length describes a small buffer on the stack.  */
		new_ptr = malloc (new_length);
		if (new_ptr == NULL)
			return false;
		memcpy (new_ptr, buffer->__space.__c, buffer->length);
	}
	else{	/* Buffer was already on the heap.  Check for overflow.  */
		if (__glibc_likely (new_length >= buffer->length))
			new_ptr = realloc (buffer->data, new_length);
		else{
			__set_errno (ENOMEM);
			new_ptr = NULL;
		}
		if (__glibc_unlikely (new_ptr == NULL)){	/* Deallocate, but buffer must remain valid to free.  */
			free (buffer->data);
			scratch_buffer_init (buffer);
			return false;
       	}
   	}	
	/* Install new heap-based buffer.  */
	buffer->data = new_ptr;
	buffer->length = new_length;
	return true;
}
```
**inchar**
```
inchar() \
	(c == EOF ?\
		((errno = inchar_errno), EOF) : ((c = _IO_getc_unlocked (s)),\
										(void)(c != EOF ?\
											++read_in : (size_t) (inchar_errno = errno))\
										,c)
```
**_io_getc_unlocked**
```
_IO_getc_unlocked(_fp) \
	(_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) ?\
		__uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++)
```

**__uflow**
```
int __uflow (FILE *fp){
	if (_IO_vtable_offset (fp) == 0 && _IO_fwide (fp, -1) != -1)
		return EOF;
	if (fp->_mode == 0)
		_IO_fwide (fp, -1);
	if (_IO_in_put_mode (fp))
		if (_IO_switch_to_get_mode (fp) == EOF)
			return EOF;
	if (fp->_IO_read_ptr < fp->_IO_read_end)
		return *(unsigned char *) fp->_IO_read_ptr++;
	if (_IO_in_backup (fp)){
		_IO_switch_to_main_get_area (fp);
		if (fp->_IO_read_ptr < fp->_IO_read_end)
			return *(unsigned char *) fp->_IO_read_ptr++;
	}
	if (_IO_have_markers (fp)){
		if (save_for_backup (fp, fp->_IO_read_end))
			return EOF;
	}
	else if (_IO_have_backup (fp))
		_IO_free_backup_area (fp);
	return _IO_UFLOW (fp);		//_IO_default_uflow
}
```
**_IO_default_uflow**
```
int _IO_default_uflow (FILE *fp){
	int ch = _IO_UNDERFLOW (fp);	//_IO_new_file_underflow
	if (ch == EOF)
		return EOF;
	return *(unsigned char *) fp->_IO_read_ptr++;
}
```
**_IO_new_file_underflow**
```
int _IO_new_file_underflow (FILE *fp){
	ssize_t count;
	if (fp->_flags & _IO_EOF_SEEN)
		return EOF;
	if (fp->_flags & _IO_NO_READS){
		fp->_flags |= _IO_ERR_SEEN;
		__set_errno (EBADF);
		return EOF;
	}
	if (fp->_IO_read_ptr < fp->_IO_read_end)
		return *(unsigned char *) fp->_IO_read_ptr;
	if (fp->_IO_buf_base == NULL){
		/* Maybe we already have a push back pointer.  */
		if (fp->_IO_save_base != NULL){
			free (fp->_IO_save_base);
			fp->_flags &= ~_IO_IN_BACKUP;
		}
		_IO_doallocbuf (fp);
	}
	if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED)){
		_IO_acquire_lock (stdout);
		if ((stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))== (_IO_LINKED | _IO_LINE_BUF))
			_IO_OVERFLOW (stdout, EOF);
			_IO_release_lock (stdout);
	}
	_IO_switch_to_get_mode (fp);
	fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
	fp->_IO_read_end = fp->_IO_buf_base;
	fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end = fp->_IO_buf_base;
	count = _IO_SYSREAD (fp, fp->_IO_buf_base,
	fp->_IO_buf_end - fp->_IO_buf_base);
	if (count <= 0){
		if (count == 0)
			fp->_flags |= _IO_EOF_SEEN;
		else
			fp->_flags |= _IO_ERR_SEEN, count = 0;
	}
	fp->_IO_read_end += count;
	if (count == 0){
		fp->_offset = _IO_pos_BAD;
		return EOF;
	}
	if (fp->_offset != _IO_pos_BAD)
		_IO_pos_adjust (fp->_offset, count);
	return *(unsigned char *) fp->_IO_read_ptr;
}
```
