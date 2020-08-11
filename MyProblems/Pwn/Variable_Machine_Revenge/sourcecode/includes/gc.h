#include <stdint.h>

#ifndef GC_
#define GC_

typedef struct garbage{
    void *ptr;
    int ref;
    struct garbage *next;
}garbage;

garbage *head;

void *gcCalloc(int count, int size);
int gcFree(void *ptr);
void *gcStart();
garbage *getHead(void *ptr);

#endif