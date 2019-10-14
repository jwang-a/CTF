#include<stdio.h>
#include<stdlib.h>


int main(){
  for(int i = 0;i<0x100;i++){
    srand(i);
    for(int j = 0;j<50;j++)
      printf("%d%c",rand()%256,j==49?'\n':',');
  }
  return 0;
}
