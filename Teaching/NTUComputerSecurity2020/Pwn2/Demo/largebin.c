#include<stdio.h>
#include<stdlib.h>

int main(){
  // Disable Buffering, ignore this
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  //prepare chunks
  char *largebin_chunks[2];
  char *guard_chunk;
  largebin_chunks[0] = malloc(0x418);
  guard_chunk = malloc(0x18);
  largebin_chunks[1] = malloc(0x428);
  guard_chunk = malloc(0x18);

  //free chunks and place them in unsorted bin
  for(int i=0;i<2;i++) free(largebin_chunks[i]);

  //malloc a large chunk to travese unsorted bin list and place chunks into large bin
  char *trigger_traverse = malloc(0x438);

  //For debugging breakpoint
  getchar();
  return 0;
}
