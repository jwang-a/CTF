/*
.POSIX:

CFLAGS = -m32 -O0 -no-pie

black_echo: black_echo.c
*/


#include <stdio.h>

int main(void)
{
    char buf[4096];

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    for (;;) {
        fgets(buf, sizeof(buf), stdin);
        printf(buf);
    }
}
