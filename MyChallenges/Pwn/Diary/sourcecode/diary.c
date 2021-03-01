/*gcc -Wl,-z,now -fpie -fstack-protector-all diary.c -o diary*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<malloc.h>

#define MAX_PAGE 14

typedef struct Diary{
  unsigned int length;
  char content[4];
}DIARY;

typedef struct Global{
  char Name[0x20];
  DIARY *MyDiary[MAX_PAGE];
  int Torn[MAX_PAGE];
  int EraserUsed;
}GLOBAL;

GLOBAL G;

void init_proc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  return;
}

void printerror(char *msg){
  puts(msg);
  exit(1);
}

void read_str(char *buf,unsigned int length){
  if(read(STDIN_FILENO,buf,length)<=0)
    printerror("Read Error");
  return;
}

int read_int(){
  char buf[8];
  memset(buf,0,8);
  read_str(buf,3);
  return atoi(buf);
}

void write_diary(){
  int page=0;
  for(page=0;page<MAX_PAGE;page++)
    if(G.MyDiary[page]==NULL && G.Torn[page]==0)
      break;
  if(page==MAX_PAGE){
    puts("Diary Full");
    return;
  }
  printf("Diary Length : ");
  unsigned int length=read_int();
  if(length>0x80){
    puts("Too much content for a single page");
    return;
  }
  G.MyDiary[page] = (DIARY*)calloc(1,length+sizeof(unsigned int));
  if(G.MyDiary[page]==NULL)
    printerror("Calloc failed");
  printf("Diary Content : ");
  G.MyDiary[page]->length = length;
  read_str(G.MyDiary[page]->content,length);
  return;
}

void read_diary(){
  printf("Page : ");
  unsigned int page=read_int();
  if(page>=MAX_PAGE || G.MyDiary[page]==NULL || G.Torn[page]==1){
    puts("Can't read page");
    return;
  }
  puts(G.MyDiary[page]->content);
  return;
}

void edit_diary(){
  if(G.EraserUsed==1){
    puts("You already used up your entire eraser");
    return;
  }
  printf("Page : ");
  int page=read_int();
  if(page>=MAX_PAGE || G.MyDiary[page]==NULL || G.Torn[page]==1){
    puts("Can't edit page");
    return;
  }
  G.EraserUsed=1;
  printf("Content : ");
  read_str(G.MyDiary[page]->content,G.MyDiary[page]->length);
  return;
}

void tear_page(){
  printf("Page : ");
  unsigned int page=read_int();
  if(page>=MAX_PAGE || G.Torn[page]==1){
    puts("Can't tear page off");
    return;
  }
  if(G.MyDiary[page]!=NULL)
    free(G.MyDiary[page]);
  G.Torn[page]=1;
  return;
}

void show_name(){
  puts(G.Name);
  return;
}

int menu(){
  puts("====================\n"
       "|       Menu       |\n"
       "====================\n"
       "| 1. Show Name     |\n"
       "| 2. Write Diary   |\n"
       "| 3. Read Diary    |\n"
       "| 4. Edit Diary    |\n"
       "| 5. Tear out page |\n"
       "| 6. Go to sleep   |\n"
       "====================");
  printf("choice : ");
  return read_int();
}

int main(){
  init_proc();
  printf("What's your name : ");
  read_str(G.Name,0x20);
  while(1){
    switch(menu()){
      case 1:
        show_name();
        break;
      case 2:
	write_diary();
        break;
      case 3:
	read_diary();
        break;
      case 4:
	edit_diary();
        break;
      case 5:
	tear_page();
	break;
      case 6:
	puts("Goodbye");
        exit(0);
      default:
	puts("Invalid choice");
        break;
    }
  }
  return 0;
}
