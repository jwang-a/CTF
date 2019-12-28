/*gcc -no-pie bookstore.c -o bookstore*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

typedef struct Book{
    int publish_year;
    char name[100];
    char description[1000];
}BOOK;



BOOK book[39] = {{1966,"Rocannon's World","\0"},
                 {1966,"Planet of Exile","\0"},
		 {1967,"City of Illusions","\0"},
		 {1969,"The Left Hand of Darkness","\0"},
                 {1974,"The Dispossessed","\0"},
		 {1976,"The Word for World is Forest","\0"},
		 {1995,"Four Ways to Forgiveness","\0"},
		 {2000,"The Telling","\0"},
		 {1968,"A Wizard of Earthsea","\0"},
                 {1970,"The Tombs of Atuan","\0"},
                 {1972,"The Farthest Shore","\0"},
                 {1990,"Tehanu","\0"},
                 {2001,"The Other Wind","\0"},
                 {1993,"The Earthsea Quartet","\0"},
                 {2001,"Tales from Earthsea","\0"},
                 {1993,"Earthsea Revisioned","\0"},
		 {1982,"The Adventure of Cobbler's Rune","\0"},
		 {1983,"Solomon Leviathan's Nine-Hundred and Thirty-First Trip Around the World","\0"},
                 {1988,"Catwings","\0"},
                 {1989,"Catwings Return","\0"},
                 {1994,"Wonderful Alexander and the Catwings","\0"},
                 {1992,"Jane On Her Own","\0"},
                 {2009,"Cat Dreams","\0"},
                 {1996,"Tales of the Catwings","\0"},
                 {2000,"More Tales of the Catwings","\0"},
                 {2004,"Gifts","\0"},
                 {2006,"Voices","\0"},
                 {2007,"Powers","\0"},
                 {2012,"Where on Earth","\0"},
                 {2012,"Outer Space, Inner Lands","\0"},
                 {1971,"The Lathe of Heaven","\0"},
                 {1976,"Very Far Away from Anywhere Else","\0"},
                 {1978,"The Eye of the Heron","\0"},
                 {1979,"Malafrena","\0"},
                 {1980,"The Beginning Place","\0"},
                 {1985,"Always Coming Home","\0"},
                 {1991,"Searoad: Chronicles of Klatsand","\0"},
                 {2003,"Changing Planes","\0"},
                 {2008,"Lavinia","\0"}};

BOOK *colle[20];

void init_proc(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    return;
}

void read_str(char *buf, int len){
    int L = read(STDIN_FILENO,buf,len)-1;
    if(buf[L]=='\n')
        buf[L] = '\0';
    return;
}

int read_int(){
    char buf[100];
    read_str(buf,16);
    return atoi(buf);
}


void add(){
    int year;
    BOOK *ptr;
    char buf[100];
    printf("What is the name of the book? ");
    read_str(buf,100);
    printf("In which year is the book published? ");
    year = read_int();
    for(int i = 0;i<39;i++)
        if((!memcmp(buf,book[i].name,strlen(buf)))&&year==book[i].publish_year){
            ptr = &book[i];
            break;
        }
    if(ptr==NULL){
	puts("Bookstore does not have the book");
	return;
    }
    for(int i = 0;i<20;i++)
	if(colle[i]==NULL){
           colle[i] = ptr;
	   puts("Successfully Added");
	   break;
        }   
    return;
}

void delete(){
    int year,idx;
    char buf[100];
    printf("What is the name of the book? ");
    read_str(buf,100);
    printf("In which year is the book published? ");
    year = read_int();
    printf("Which copy(idx) do you want to delete? ");
    idx = read_int();
    if(idx<0 || idx>20){
        puts("Invalid index");
	return;
    }
    if(colle[idx]!=NULL&&(!memcmp(buf,colle[idx]->name,strlen(buf)))&&year==colle[idx]->publish_year){
        colle[idx] = NULL;
        puts("Successfully deleted");
    }
    return;
}

void update(){
    int year;
    char buf[100];
    printf("What is the name of the book? ");
    read_str(buf,100);
    printf("In which year is the book published? ");
    year = read_int();
    for(int i = 0;i<20;i++){
        if(colle[i]!=NULL&&(!memcmp(buf,colle[i]->name,strlen(buf)))&&year==colle[i]->publish_year){
           printf("Description : ");
           read_str(colle[i]->description,990);
	   puts("Description updated");
	   break;
        }   
    }
    return;
}

void show(){
    for(int i = 0;i<20;i++){
	printf("%2d : ",i);
        if(colle[i]!=NULL){
            printf("%s\n",colle[i]->name);
            printf("     %d\n",colle[i]->publish_year);
            printf("     %s\n",colle[i]->description);
        }
	else
            puts("");
	puts("");
    }
    return;
}

int menu(){
    puts("           Action List          ");
    puts("                                ");
    puts("  1. Add book to collection     ");
    puts("  2. Remove book from collection");
    puts("  3. Update book description    ");
    puts("  4. Show book description      ");
    puts("  5. Leave                      ");
    puts("                                ");
    printf("Choice : ");
    return read_int();
}

int main(){
    init_proc();
    while(1){
        int action = menu();
	switch(action){
            case 1:
		add();
		break;
	    case 2:
		delete();
		break;
	    case 3:
		update();
		break;
	    case 4:
		show();
		break;
	    case 5:
		puts("Goodbye");
		return 0;
	    default:
                puts("Invalid Option");
        }
    }
    return 0;
}
