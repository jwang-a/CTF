/*gcc -Wl,-z,relro,-z,now -fstack-protector fmt.c -o fmt*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/mman.h>
#include<unistd.h>

char QUESTION[2][64] = {"What is your name? \0","Forgive my poor memory, what is your name again? \0"};
char GREETING[2][16] = {"hello, \0","goodbye, \0"};

void init_proc(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    mprotect((char*)(((unsigned long long int)QUESTION)&0xfffffffffffff000),0x1000,PROT_READ);
    return;
}

int main(){
    init_proc();
    char name[40];
    for(int i = 0;i<2;i++){
	printf(QUESTION[i]);
        read(STDIN_FILENO,name,32);
        printf(GREETING[i]);
        printf(name);
    }
    printf("See you next time : )\n");
    exit(0);
}
