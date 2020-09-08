#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "../includes/gc.h"
#include "../includes/vm.h"

extern void usleep( unsigned long useconds);

garbage *getHead(void *ptr){
    garbage *current = NULL; 
    current = head;
    while(1){
        if(current->next == NULL) return current;  
        else if(current->ptr == ptr) return current;
        else current = current->next;
    }
}


void *gcCalloc(int count, int size){
    void *ptr = (void *)malloc(count * size);
    memset(ptr, 0, count * size);
    garbage *current = getHead(0);
    current->next = (garbage *)calloc(1, sizeof(garbage));
    current->next->ptr = ptr;
    current->next->ref = 1;
    return ptr;
}

int gcFree(void *ptr){
    garbage *current = getHead(ptr);    
    current->ref = 0;
    return 1;
}

void *gcStart(){
    garbage *current; 
    head = (garbage *)calloc(1, sizeof(garbage));
    head->ptr = "HEAD";
    head->ref = -2;
    while(1){
        current = head;
        while(1){
            if(current == NULL) break;
            else if(current->ref == 0) {
                free(current->ptr);
                current->ref = -1;
            }
            else {
                current = current->next;
            }
        }
    }
}