#include<stdio.h>
#include<stdlib.h>

int main(){
  // Disable Buffering, ignore this
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  //prepare chunks
  char *tcache_chunks[7];
  char *unsortedbin_chunks[2];
  unsortedbin_chunks[0] = malloc(0x88);
  char *guard_chunk = malloc(0x18);
  unsortedbin_chunks[1] = malloc(0x418);
  for(int i=0;i<7;i++) tcache_chunks[i] = malloc(0x88);

  //free chunks and place them in tcache/unsorted bin
  for(int i=0;i<7;i++) free(tcache_chunks[i]);
  for(int i=0;i<2;i++) free(unsortedbin_chunks[i]);

  //For debugging breakpoint
  getchar();
  return 0;
}
