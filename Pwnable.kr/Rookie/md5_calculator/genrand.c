#include<stdio.h>
#include<stdlib.h>
#include<time.h>

int main(){
	srand(time(NULL));
	for(int i = 0;i<8;i++)
		printf("%d\n",rand());
	return 0;
}
