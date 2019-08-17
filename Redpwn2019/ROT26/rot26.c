#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *ualphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char *lalphabet = "abcdefghijklmnopqrstuvwxyz";

char *rot26(char *dst, char *src, size_t n)
{
	int i, x;

	for (i = 0; i < n; i++) {
		if (isupper(src[i])) {
			x = ualphabet[((src[i] - 'A') + 26) % strlen(ualphabet)];
		} else if (islower(src[i])) {
			x = lalphabet[((src[i] - 'a') + 26) % strlen(lalphabet)];
		} else {
			x = src[i];
		}
		dst[i] = x;
	}
}

void winners_room(void)
{
	puts("Please, take a shell!");
	system("/bin/sh");
	exit(EXIT_SUCCESS);
}

int main(void)
{
	char buf[4096];
	char sanitized[4096];

	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);

	fgets(buf, sizeof(buf), stdin);
	rot26(sanitized, buf, sizeof(sanitized));
	printf(sanitized);
	exit(EXIT_FAILURE);
}
