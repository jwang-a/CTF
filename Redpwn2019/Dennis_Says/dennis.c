#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct spm {
	struct spm *spm;
	struct spm *spmm;
} *spm;

static void greet(void)
{
	char buf[1024];

	puts("Dennis greet");
	printf("How much greet? : ");
	fgets(buf, sizeof(buf), stdin);
	spm = malloc(atoi(buf));
}

static void writ(void)
{
	char buf[1024];

	puts("Dennis writ");
	printf("How much writ? : ");
	fgets(buf, sizeof(buf), stdin);
	write(1, spm, atoi(buf));
}

static void yeet(void)
{
	puts("Dennis yeet");
	memcpy(spm->spmm, spm, sizeof(spm));
}

static void eat(void)
{
	puts("Dennis eat");
	printf("Pizza: ");
	gets(spm);
}

static void delet(void)
{
	puts("Dennis delet");
	free(spm);
}

static void repeat(void)
{
	char buf[1024];

	puts("Dennis repeat");
	fgets(buf, sizeof(buf), stdin);
	fputs(buf, stderr);
}

static void bye_bye(void)
{
	puts("Dennis bids farewell");
	exit(EXIT_SUCCESS);
}

static void print_menu(void)
{
	putchar('\n');
	puts("--Commands-----");
	puts("   1. greet");
	puts("   2. writ");
	puts("   3. yeet");
	puts("   4. eat");
	puts("   5. delet");
	puts("   6. repeat");
	puts("   7. bye bye");
	puts("---------------");
	putchar('\n');
}

static void tick(void)
{
	int c;
	char cmd[16];

	printf("Command me: ");
	fgets(cmd, sizeof(cmd), stdin);
	c = cmd[0];
	switch (c) {
	case '1':
		greet();
		break;
	case '2':
		writ();
		break;
	case '3':
		yeet();
		break;
	case '4':
		eat();
		break;
	case '5':
		delet();
		break;
	case '6':
		repeat();
		break;
	case '7':
		bye_bye();
		break;
	default:
		puts("What?");
	}
}

int main(void)
{
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);

	print_menu();
	for (;;) {
		tick();
	}
}
