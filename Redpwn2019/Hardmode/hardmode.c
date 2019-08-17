#include <stdio.h>
#include <stdlib.h>

static void vuln(void)
{
	char buf[22];

	gets(buf);
	system("//////bin///sh # hs\\\nib\\\\\\"); // wut
}

int main(void)
{
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);
	puts("Welcome to my fiendish little challenge");
	vuln();
}
