/*gcc -fno-stack-protector -no-pie bof.c -o bof*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

char name[16];

void special_treat(){
    printf("You want some special treat?\nHere you go\n");
    system(getenv("TREAT"));
    return;
}

void get_inp(char *target){
    char buf;
    int idx=0;
    while(1){
        buf = getchar();
	target[idx] = buf;
	idx++;
	if(buf=='\0'||buf=='\n'){
            target[idx-1] = '\0';
	    while(idx%8!=0){
                target[idx] = '\0';
		idx++;
            }
	    break;
        }
    }
    return;
}

void menu(){
    printf("Menu\n");
    printf("====================\n");
    printf("||  1.apple       ||\n");
    printf("||  2.coffee      ||\n");
    printf("||  3.hamburger   ||\n");
    printf("====================\n");
    printf("\n\nWhat treat would you like? (1~3) : ");
    return;
}

void init_proc(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    return;
}

int main(){
    init_proc();
    char buf[64];
    printf("What is your name : ");
    get_inp(name);
    printf("Nice to meet you %s, What treat would you like?",name);
    menu();
    get_inp(buf);
    if(buf[0]=='1'){
        printf("Here is your apple\n\n");
        printf("                                     ___\n");
        printf("                          _/`.-'`.      \n");
        printf("                _      _/` .  _.'       \n");
        printf("       ..:::::.(_)   /` _.'_./          \n");
        printf("     .oooooooooo\\ \\o/.-'__.'o.        \n");
        printf("    .ooooooooo`._\\_|_.'`oooooob.       \n");
        printf("  .ooooooooooooooooooooo&&oooooob.      \n");
        printf(" .oooooooooooooooooooo&@@@@@@oooob.     \n");
        printf(".ooooooooooooooooooooooo&&@@@@@ooob.    \n");
        printf("doooooooooooooooooooooooooo&@@@@ooob    \n");
        printf("doooooooooooooooooooooooooo&@@@oooob    \n");
        printf("dooooooooooooooooooooooooo&@@@ooooob    \n");
        printf("dooooooooooooooooooooooooo&@@oooooob    \n");
        printf("`dooooooooooooooooooooooooo&@ooooob'    \n");
        printf(" `doooooooooooooooooooooooooooooob'     \n");
        printf("  `doooooooooooooooooooooooooooob'      \n");
        printf("   `doooooooooooooooooooooooooob'       \n");
        printf("    `doooooooooooooooooooooooob'        \n");
        printf("     `doooooooooooooooooooooob'         \n");
        printf("      `dooooooooobodoooooooob'          \n");
        printf("       `doooooooob dooooooob'           \n");
        printf("         `\"\"\"\"\"\"\"' `\"\"\"\"\"\"'\n");
    }
    else if(buf[0]=='2'){
        printf("Here is your coffee\n\n");
        printf("                     (                                    \n");
        printf("                       )     (                            \n");
        printf("                ___...(-------)-....___                   \n");
        printf("            .-\"\"       )    (          \"\"-.           \n");
        printf("      .-'``'|-._             )         _.-|               \n");
        printf("     /  .--.|   `\"\"---...........---\"\"`   |           \n");
        printf("    /  /    |                             |               \n");
        printf("    |  |    |                             |               \n");
        printf("     \\  \\   |                             |             \n");
        printf("      `\\ `\\ |                             |             \n");
        printf("        `\\ `|                             |              \n");
        printf("        _/ /\\                             /              \n");
        printf("       (__/  \\                           /               \n");
        printf("    _..---\"\"` \\                         /`\"\"---.._   \n");
        printf(" .-'           \\                       /          '-.    \n");
        printf(":               `-.__             __.-'              :    \n");
        printf(":                  ) \"\"---...---\"\" (                 :\n");
        printf(" '._               `\"--...___...--\"`              _.'   \n");
        printf("   \\\"\"--..__                              __..--\"\"/  \n");
        printf("    '._     \"\"\"----.....______.....----\"\"\"     _.'  \n");
        printf("       `\"\"--..,,_____            _____,,..--\"\"`       \n");
        printf("                     `\"\"\"----\"\"\"`                   \n");
    }
    else if(buf[0]=='3'){
        printf("Here is your hamburger\n\n");
        printf("        _....----\"\"\"----...._      \n");
        printf("     .-'  o    o    o    o   '-.      \n");
        printf("    /  o    o    o         o    \\    \n");
        printf(" __/__o___o_ _ o___ _ o_ o_ _ _o_\\__:\n");
        printf("/                                   \\\n");
        printf("\\___________________________________/\n");
        printf("  \\~`-`.__.`-~`._.~`-`~.-~.__.~`-`/  \n");
        printf("   \\                             /   \n");
        printf("    `-._______________________.-'     \n");
    }
    else{
        printf("What in the hell did you order???\n");
        exit(0);
    }
    printf("Please give us some feedback : ");
    get_inp(buf);
    printf("Hope you have a nice day :)\n");
    return 0;
}
