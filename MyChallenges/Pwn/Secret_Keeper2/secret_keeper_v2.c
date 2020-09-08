/*gcc -Wl,-z,relro,-z,now -fno-stack-protector secret_keeper_v2.c -o secret_keeper_v2*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<stdint.h>

typedef struct Secret{
    uint16_t len;
    uint16_t nlen;
    char *name;
    char *content;
}SECRET;

int pass = 0;
SECRET *sec=NULL;

void init_proc(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    return;
}

void read_str(char *buf,int len){
    int L = read(STDIN_FILENO,buf,len)-1;
    if(buf[L]=='\n')
        buf[L]='\0';
    return;
}

int read_int(){
    char buf[8];
    read_str(buf,4);
    return atoi(buf);
}

int menu(){
    puts("       Secrets         ");
    puts(" 1. Store some secret  ");
    puts(" 2. Show some secret   ");
    puts(" 3. Destroy some secret");
    puts(" 4. Spill some secret  ");
    puts(" 5. Exit               ");
    return read_int();
}

void store(){
    if(sec!=NULL){
        if(pass==0){
            puts("Only one secret per person is our policy here, but I'll let you off this time");
	    pass=1;
        }
	else{
            puts("You already stored a secret");
	    return;
        }
    }
    sec = (SECRET*)malloc(sizeof(SECRET));
    printf("How long is your secret? ");
    sec->len = read_int();
    sec->content = (char*)malloc(sizeof(char)*sec->len);
    printf("Give us your secret : ");
    read_str(sec->content,sec->len);
    printf("How long is your name? ");
    sec->nlen = read_int();
    sec->name = (char*)malloc(sec->nlen);
    printf("Give us your name : ");
    read_str(sec->name,sec->nlen);
    return;
}

void show(){
    printf("You asked for secret of ");
    write(STDOUT_FILENO,sec->name,sec->len);
    puts("\nPeeking at secrets is not good\n");
    fclose(stdout);
    return;
}

void destroy(){
    memset(sec->name,0,sec->nlen);
    free(sec->name);
    memset(sec->content,0,sec->len);
    free(sec->content);
    memset(sec,0,sizeof(SECRET));
    free(sec);
    return;
}

void spill(){
    puts("Spilling secrets is not good\n");
    fclose(stdin);
    char buf[9970];
    memcpy(buf,sec->content,sec->len);
    memset(sec->name,0,sec->nlen);
    memset(sec->content,0,sec->len);
    return;
}

int main(){
    init_proc();
    while(1){
        int res = menu();
        switch(res){
            case 1:
                store();
                break;
            case 2:
				show();
                break;
            case 3:
                destroy();
				break;
            case 4:
				spill();
			case 5:
				puts("Goodbye");
				return 0;
            default:
				puts("Invalid Option");
        }
    }
    return 0;
}
