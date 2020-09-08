/*gcc -Wl,-z,now -fpie -fstack-protector-all oldnote.c -o oldnote*/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

#define MAX_ENTRY 4

char *Note[MAX_ENTRY]={NULL};

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  return;
}

void printerror(char *msg){
  puts(msg);
  exit(1);
}

void readstr(char *buf,unsigned int length){
  if(read(STDIN_FILENO,buf,length)<=0)
    printerror("read error");
  return;
}

int readint(){
  char buf[0x8];
  memset(buf,0,8);
  readstr(buf,7);
  return atoi(buf);
}

void new_note(){
  int idx;
  for(idx = 0;idx<MAX_ENTRY;idx++)
    if(Note[idx]==NULL)
      break;
  if(idx==MAX_ENTRY){
    puts("No more space");
    return;
  }
  printf("Note size : ");
  int size=readint();
  if(size>=0x100){
    puts("Maximum note size exceeded");
    return;
  }
  Note[idx] = malloc(size);
  if(Note[idx]==NULL)
    printerror("malloc error");
  printf("Note : ");
  readstr(Note[idx],size);
  return;
}

void delete_note(){
  printf("Note idx : ");
  int idx = readint();
  if(idx<0 || idx>=MAX_ENTRY || Note[idx]==NULL){
    puts("Invalid Index");
    return;
  }
  free(Note[idx]);
  Note[idx] = NULL;
  return;
}

int menu(){
  puts("==================");
  puts("|      menu      |");
  puts("==================");
  puts("| 1. new note    |");
  puts("| 2. delete note |");
  puts("| 3. give up     |");
  puts("==================");
  printf("choice : ");
  return readint();
}

int main(){
  initproc();
  while(1){
    switch(menu()){
      case 1:
        new_note();
	break;
      case 2:
	delete_note();
	break;
      case 3:
       puts("Goodbye");
       exit(0);
      case 4:
       puts("Invalid choice");
       break;
    }
  }
  return 0;
}
