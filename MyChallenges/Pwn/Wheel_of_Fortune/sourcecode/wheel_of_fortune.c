#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void init_proc(){
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stderr,NULL,_IONBF,0);
    return;
}

unsigned int read_int(){
    char buf[20];
    int cnt=0;
    buf[cnt] = getchar();
    while(buf[cnt]=='\n')
        buf[cnt] = getchar();
    while(buf[cnt]!='\n' && cnt<19){
        cnt+=1;
        buf[cnt] = getchar();
    }
    buf[cnt] = '\0';
    return (unsigned int)atoi(buf);
}

unsigned char read_char(){
    char buf;
    buf = getchar();
    while(buf=='\n'){
        buf = getchar();
    }
    return buf;
}

unsigned int menu(){
    puts("\n\n");
    puts("\033[1;31m        ▄▄▌ ▐ ▄▌ ▄ .▄▄▄▄ .▄▄▄ .▄▄▌     \033[0m");
    puts("\033[1;31m        ██· █▌▐███▪▐█▀▄.▀·▀▄.▀·██•     \033[0m");
    puts("\033[1;31m        ██▪▐█▐▐▌██▀▐█▐▀▀▪▄▐▀▀▪▄██▪     \033[0m");
    puts("\033[1;31m        ▐█▌██▐█▌██▌▐▀▐█▄▄▌▐█▄▄▌▐█▌▐▌   \033[0m");
    puts("\033[1;31m         ▀▀▀▀ ▀▪▀▀▀ · ▀▀▀  ▀▀▀ .▀▀▀    \033[0m");
    puts("\033[1;33m                      ·▄▄▄             \033[0m");
    puts("\033[1;33m                ▪     ▐▄▄·             \033[0m");
    puts("\033[1;33m                 ▄█▀▄ ██▪              \033[0m");
    puts("\033[1;33m                ▐█▌.▐▌██▌.             \033[0m");
    puts("\033[1;33m                 ▀█▄▀▪▀▀▀              \033[0m");
    puts("\033[1;31m    ·▄▄▄      ▄▄▄  ▄▄▄▄▄▄• ▄▌ ▐ ▄ ▄▄▄ .\033[0m");
    puts("\033[1;31m    ▐▄▄·▪     ▀▄ █·•██  █▪██▌•█▌▐█▀▄.▀·\033[0m");
    puts("\033[1;31m    ██▪  ▄█▀▄ ▐▀▀▄  ▐█.▪█▌▐█▌▐█▐▐▌▐▀▀▪▄\033[0m");
    puts("\033[1;31m    ██▌.▐█▌.▐▌▐█•█▌ ▐█▌·▐█▄█▌██▐█▌▐█▄▄▌\033[0m");
    puts("\033[1;31m    ▀▀▀  ▀█▄▀▪.▀  ▀ ▀▀▀  ▀▀▀ ▀▀ █▪ ▀▀▀ \033[0m");
    puts("\n");
    printf("Give me a number and I will tell your fortune : ");;
    return read_int();
}

void run_wheel(unsigned int num){
  int fortune_state = 0,fortune_pointer=0,instruction_pointer=0,state_pointer=1,inp;
  int state[256] = {0};
  int instruction[32]={0};
  unsigned char fortune_tape[1000]={0};
  for(int i = 0;i<32;i++){
    instruction[i] = num&1;
    num>>=1;
  }
  while(instruction_pointer<32){
    if(instruction[instruction_pointer]&1)
      fortune_state = (fortune_state+1)%8;
	else
      fortune_state = (fortune_state+7)%8;
	state[state_pointer] = fortune_state;
    switch(fortune_state){
      case 0:
        fortune_pointer--;
		break;
      case 1:
		fortune_pointer++;
		break;
      case 2:
		fortune_tape[fortune_pointer]++;
		break;
      case 3:
		fortune_tape[fortune_pointer]--;
		break;
      case 4:
		state_pointer = (state_pointer+256-fortune_tape[fortune_pointer])%256;
		fortune_state = state[state_pointer];
		instruction_pointer-=fortune_tape[fortune_pointer];
		break;
      case 5:
		printf("The wheel wants your lucky number : ");
		fortune_state^=1<<(read_int()%3);
		state[state_pointer] = fortune_state;
		switch(fortune_state){
          case 1:
            fortune_pointer++;
            break;
          case 4:
            state_pointer = (state_pointer+256-fortune_tape[fortune_pointer])%256;
            fortune_state = state[state_pointer];
            instruction_pointer-=fortune_tape[fortune_pointer];
			break;
          case 7:
            putchar(fortune_tape[fortune_pointer]);
			break;
          default:
			puts("Bad bad luck :(");
			return;
		}
		break;
      case 6:
		printf("The wheel wants your lucky token : ");
		fortune_tape[fortune_pointer] = read_char();
		break;
      case 7:
		printf("ƒ %c ƒ\n",fortune_tape[fortune_pointer]);
		break;
      default:
		puts("Bad bad luck :(");
		return;
	}
	state_pointer = (state_pointer+1)%256;
	instruction_pointer+=1;
  }
  if(fortune_tape[fortune_pointer]==127 || fortune_tape[fortune_pointer]==128)
    puts("Unbelievable! Where did you get those good fortune?");
  if(fortune_tape[fortune_pointer]==126 || fortune_tape[fortune_pointer]==129)
    puts("Well, not the best, but enough for normal people like you and me.");
  else{
    puts("The worst I have ever seen...");
    puts("But don't worry, here are some fortune cookies to boost your luck!");
	puts("And they only cost $100 each!!");
  }
  return;
}


int main(){
    init_proc();
    run_wheel(menu());
    return 0;
}
