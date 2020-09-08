#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>

#include "../includes/vm.h"
#include "../includes/gc.h"


int init(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    pthread_t p_thread;
    if(pthread_create(&p_thread, NULL, gcStart, 0) < 0) exit(-1);
    pthread_detach(p_thread);
    return 0;
}

int scan(char *buf, int len){
    int res = read(0, buf, len);
    if(buf[res - 1] == 0xa) buf[res - 1] = 0;
    return res;
}

int main(int argc, char *argv[]){
    size_t opcode;
    char *code;
    int res;
    init();

    code = (char *)calloc(1, 0x2000);
    printf("Code :> ");
    
    res = scan(code, 0x2000);
    printf("\n-----------------------\n");

    if(initVm(code, res)){
        exit(-1);
    }
    
    while((opcode = fetch()) != 0){
        if(execute(opcode) == 0){
            exit(-1);
        }
    }
    return 0;
}