#include<stdio.h>
#include<stdlib.h>

int main(){
  //disable Buffering, ignore this
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  //prepare chunks
  char *tcache_chunks[7];
  char *fastbin_chunks[2];
  for(int i=0;i<7;i++) tcache_chunks[i] = malloc(0x18);
  for(int i=0;i<2;i++) fastbin_chunks[i] = malloc(0x18);

  //free chunks and place them in tcache/fastbin
  for(int i=0;i<7;i++) free(tcache_chunks[i]);
  for(int i=0;i<2;i++) free(fastbin_chunks[i]);

  //debugging breakpoint
  getchar();
  return 0;
}
