#include<stdio.h>
#include<stdlib.h>

int main(){
  //disable Buffering, ignore this
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  //chunkA -> freed chunk
  //chunkB -> allocated chunk
  char *chunkA = malloc(0x418);
  char *chunkB = malloc(0x18);
  free(chunkA);

  //display address for faster demo
  printf("allocated chunk : %p\n",chunkB-0x10);
  printf("freed chunk : %p\n",chunkA-0x10);
  printf("top chunk : %p\n", chunkA+0x410);

  //debugging breakpoint
  getchar();
  return 0;
}
