#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    alarm(60);
    printf("it worked\n");
    execl("./notepad", NULL, NULL);
}
