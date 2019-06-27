#include <iostream>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string>
#include "memory.h"
#include <malloc.h>
#include <stdlib.h>
#include <sstream>
#include <vector>

using namespace std;

#define FLAGLEN 32
#define TIMEOUT 60

class Ghost {
	public :
		Ghost():name(NULL),age(0){
			type = "Ghost";
		};

		Ghost(const Ghost &copyghost){
			name = new char[strlen(copyghost.name) + 1] ;
			strcpy(name,copyghost.name) ;
			type = copyghost.type;
			age = copyghost.age ;
			msg = copyghost.msg ;
		}

		Ghost& operator=(const Ghost &copyghost){
			name = new char[strlen(copyghost.name) + 1] ;
			strcpy(name,copyghost.name) ;
			type = copyghost.type;
			age = copyghost.age ;
			msg = copyghost.msg ;
		}
		
		char *getname(){
			return name ;
		}

		string gettype(){
			return type ;
		}


		virtual void speak(){
			cout << "<<" <<  name << ">>" <<" speak : " << msg << endl;
		};
		virtual int changemsg(string str){
			msg = str ;
			return 1 ;
		}

		virtual void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	

		}

		virtual ~Ghost(){
			age = 0 ;
			msg.clear();
			type.clear();
			memset(name,0,malloc_usable_size(name));
			delete[] name ;
		};

	protected :
		int age ;
		char *name ;
		string type ;
		string msg ;

};

class Vampire : public Ghost {
	public :
		Vampire():blood(NULL){
			type = "Vampire" ;
		};
		
		Vampire(int ghostage,string ghostname,string ghostmsg){
			type = "Vampire";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strcpy(name,ghostname.c_str());
			msg = ghostmsg ;
			blood = NULL ;
		};

		void addblood(string com){
			blood = new char[com.length()+1];
			memcpy(blood,com.c_str(),com.length());
		}


		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "Blood : " << blood << endl ;
		}
		~Vampire(){
			delete[] blood;
		};
	private :
		char *blood ;
};

class Mummy : public Ghost {
	public :
		Mummy(){
			type = "Mummy" ;
		};
		
		Mummy(int ghostage,string ghostname,string ghostmsg){
			type = "Mummy";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			memcpy(name,ghostname.c_str(),ghostname.length());
			msg = ghostmsg ;
		};

		void addbandage(string ban){
			bandage = ban ;
		}


		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "Bandage : " << bandage << endl ;
		}
		~Mummy(){
			bandage.clear();
		};
	private :
		string bandage ;
};

class Dullahan : public Ghost {
	public :
		Dullahan(){
			type = "Dullahan" ;
		};
		
		Dullahan(int ghostage,string ghostname,string ghostmsg){
			type = "Dullahan";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strcpy(name,ghostname.c_str());
			msg = ghostmsg ;
		};

		void addweapon(string arms){
			weapon = arms ;
		}

		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "Weapon : " << weapon << endl ;
		}
		~Dullahan(){
			weapon.clear();
		};
	private :
		string weapon ;
};

class Skull : public Ghost {
	public :
		Skull():bones(0){
			type = "Skull" ;
		};
		
		Skull(int ghostage,string ghostname,string ghostmsg){
			type = "Skull";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strncpy(name,ghostname.c_str(),ghostname.length());
			msg = ghostmsg ;
			bones = 0 ;
		};

		void addbone(int ghostbone){
			bones = ghostbone ;	
		}


		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "Bones : " << bones << endl ;
		}
		~Skull(){
			bones = 0 ;
		};
	private :
		int bones ;
};

class Alan : public Ghost {
	public :
		Alan():lightsaber(NULL){
			type = "Alan" ;
		};
		
		Alan(int ghostage,string ghostname,string ghostmsg){
			type = "Alan";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strcpy(name,ghostname.c_str());
			msg = ghostmsg ;
		};

		void addlightsaber(string str){
			lightsaber = (char*)str.c_str();		
		}

		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "Lightsaber : " << lightsaber << endl ;
		}
		~Alan(){
		};
	private :
		char *lightsaber ;
};

class Yuki : public Ghost {
	public :
		Yuki(){
			type = "Yuki-onna" ;
		};
		
		Yuki(int ghostage,string ghostname,string ghostmsg){
			type = "Yuki-onna";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strcpy(name,ghostname.c_str());
			msg = ghostmsg ;
		};

		void addcold(string str){
			cold = str ;
			cout << "So cold........" << endl ;
			cout << cold << endl ;
		}

		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "Cold : " << cold << endl ;
		}
		~Yuki(){
			cold.clear();
		};
	private :
		string cold ;
};

class Kasa : public Ghost {
	public :
		Kasa(){
			type = "Kasa-obake" ;
		};
		
		Kasa(int ghostage,string ghostname,string ghostmsg){
			type = "Kasa-obake";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strcpy(name,ghostname.c_str());
			msg = ghostmsg ;
		};

		void addinfo(int ghostfoot,string str){
			unsigned int size = 0 ;
			char buf[20] ;
			foot = ghostfoot ;
			eyes = str ;
			cout << "Input to echo :" ;
			size = read(0,buf,20);
			buf[size] = 0;
			cout << "echo :" << buf << endl ;	
		};

		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "Foot : " << foot << endl ;
			cout << "Eyes : " << eyes << endl ;
		}
		~Kasa(){
			foot = 0 ;
			eyes.clear();
		};
	private :
		int foot ;
		string eyes ;
};

class Devil : public Ghost{
	public :
		Devil():power(NULL){
			type = "Devil" ;
		};

		Devil(int ghostage,string ghostname,string ghostmsg){
			type = "Devil";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strcpy(name,ghostname.c_str());
			msg = ghostmsg ;
			power = NULL ;
		};

		Devil(const Devil &copyghost){
			name = new char[strlen(copyghost.name) + 1] ;
			strcpy(name,copyghost.name) ;
			type = copyghost.type;
			age = copyghost.age ;
			msg = copyghost.msg ;
			power = new char[strlen(copyghost.power)+1];
			strcpy(power,copyghost.power);

		};

		void addpower(string str){
			stringstream ss ;
			power = new char[str.length()+1];
			memcpy(power,str.c_str(),str.length());
			cout << "Your power : " << power << endl ;
		};

		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "power : " << power << endl ;
		}

		~Devil(){
			delete[] power;
		};
	private :
		char *power ;
};

class Werewolf : public Ghost{
	public :
		Werewolf():trans(0){
			type = "Werewolf" ;
		};

		Werewolf(int ghostage,string ghostname,string ghostmsg){
			type = "Werewolf";
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strcpy(name,ghostname.c_str());
			msg = ghostmsg ;
			trans = 0 ;
		};

		Werewolf(const Werewolf &copyghost){
			name = new char[strlen(copyghost.name) + 1] ;
			strcpy(name,copyghost.name) ;
			type = copyghost.type;
			age = copyghost.age ;
			msg = copyghost.msg ;
			trans = copyghost.trans ;
		};

		void speak(){
			
			cout << "<<" << name << ">>" << " speak : ";
			if(trans == 1){
				cout << flush ;
				cout << msg ;
			}else{
				cout << "Oh ~ " << msg ;
			}
			cout << endl ;
		};


		void addtrans(int ghosttrans){
			trans = ghosttrans ;
			if(trans == 1)
				msg = "Wow Wow Wowwwwwwwww" ;
		};

		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;
			if(trans == 1){	
				cout << "Full moon : " << "Yes" << endl ;
			}else{
				cout << "Full moon : " << "No" << endl ;
			}
		}

		~Werewolf(){
			trans = 0 ;
		};
	private :
		int trans ;

};

class Zombie : public Ghost {
	public :
		Zombie():secret(NULL){
			type = "Zombie" ;
		}

		Zombie(int ghostage,string ghostname,string ghostmsg){
			type = "Zombie" ;
			age = ghostage ;
			name = new char[ghostname.length() + 1];
			strcpy(name,ghostname.c_str());
			msg = ghostmsg ;
			secret = NULL ;
			
		}

		Zombie(const Zombie &copyghost){
			name = new char[strlen(copyghost.name) + 1] ;
			strcpy(name,copyghost.name) ;
			type = copyghost.type;
			age = copyghost.age ;
			msg = copyghost.msg ;
			secret = new char[strlen(copyghost.secret)+1];
			strcpy(secret,copyghost.secret);

		}
	
		void speak(){
			cout << "<<" <<  name << ">>" <<" speak : " << msg << endl;
		};

		bool addsecret(){
			int i,fd , sfd;
			unsigned char buf[32],sbuf[32];
			secret = new char[2*FLAGLEN+1] ;
			fd = open("/dev/urandom",O_RDONLY);
			sfd = open("/home/flags/ghostparty",O_RDONLY);
			if(fd == -1 || sfd == -1) return 0 ;
			read(fd,buf,FLAGLEN);
			read(sfd,sbuf,FLAGLEN);
			for(i = 0 ; i < FLAGLEN ; i++){
				sprintf(secret+2*i	,"%02X",(buf[i]^sbuf[i]));
			}
			lseek(sfd,0,0);
			memset(sbuf,0,32);
			memset(buf,0,32);
			close(fd);

			return 1;
		}

		void ghostinfo(){
			cout << "Type : " << type << endl ;
			cout << "Name : " << name << endl ;
			cout << "Age : " << age << endl ;	
			cout << "secret : " << secret << endl ;
		}
		~Zombie(){
			delete[] secret ;
		}
	private :
		char *secret ;
};


vector<Ghost *> ghostlist ;


template <class T>
void speaking(T ghost){
	ghost.speak();
};

void night(){
	unsigned int num ;
	vector<Ghost *>::iterator iter ;
	for(iter = ghostlist.begin();iter != ghostlist.end() ; iter++){
		num = 31+rand()%7;
		cout << "\033[" <<  num << "m";
		speaking(**iter);
		cout << "\033[0m";
	}
}


void menu(){
	cout << endl ;
	cout << "§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§" << endl ;
	cout << "                GHOST PARTY                " << endl ;
	cout << "§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§" << endl ;
	cout << "§                                         §" << endl ;
	cout << "§  1. Add a ghost to the party            §" << endl ;
	cout << "§  2. Show ghost's info                   §" << endl ;
	cout << "§  3. Night Parade of One Hundred Demons  §" << endl ;
	cout << "§  4. Remove a ghost from the party       §" << endl ;
	cout << "§  5. End the party                       §" << endl ;
    cout << "§                                         §" << endl ;	
	cout << "§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§" << endl ;
	cout << endl ;

};


void typelist(){
	cout << "-----------------" << endl ;
	cout << " 1.Werewolf      " << endl ;
	cout << " 2.Devil         " << endl ;
	cout << " 3.Zombie        " << endl ;
	cout << " 4.Skull         " << endl ;
	cout << " 5.Mummy         " << endl ;
	cout << " 6.Dullahan      " << endl ;
	cout << " 7.Vampire       " << endl ;
	cout << " 8.Yuki-onna     " << endl ;
	cout << " 9.Kasa-obake    " << endl ;
	cout << " 10.Alan         " << endl ;
	cout << "-----------------" << endl ;
}

template <class T>
int smalllist(T ghost){
	unsigned int choice ;
	cout << "1.Join       " << endl;
	cout << "2.Give up" << endl ;
	cout << "3.Join and hear what the ghost say" << endl ;
	cout << "Your choice : " ;
	cin >> choice ;
	if(!cin.good()){
		cout << "Format error !" << endl ;
		exit(0);
	}

	switch(choice){
		case 1 :
			ghostlist.push_back(ghost);
			cout << "\033[32mThe ghost is joining the party\033[0m" << endl ;
			return 1 ;
			break ;
		case 2 :
			cout << "\033[31mThe ghost is not joining the party\033[0m" << endl ;
			delete ghost ;
			return 0 ;
			break ;
		case 3 :
			ghostlist.push_back(ghost);
			speaking(*ghost);
			cout << "\033[32mThe ghost is joining the party\033[0m" << endl ;
			return 1;
			break ;
		default :
			cout << "\033[31mInvaild choice\033[0m" << endl ;
			delete ghost ;
			return 0 ;
			break ;

	}
}

int addghost(){
	unsigned int choice ;
	string name ;
	string message ;
	int age ;

	cout << "Name : " ;
	cin >> name ;

	cout << "Age : " ;
	cin >> age ;

	cout << "Message : " ;
	cin.ignore();
	getline(cin,message);

	typelist();
	cout << "Choose a type of ghost :" ; 
	cin >> choice ;
	
	switch(choice){
		case 1 :
			{
			int trans ;
			Werewolf *ghost = new Werewolf(age,name,message);
			cout << "Full moon ? (1:yes/0:no):" ;
			cin >> trans ;
			ghost->addtrans(trans) ;
			smalllist(ghost);
			break ;
			}
		case 2 :
			{
			string power ;
			Devil *ghost = new Devil(age,name,message);
			cout << "Add power : " ;
			cin.ignore();
			getline(cin,power) ;
			ghost->addpower(power);
			smalllist(ghost);
			break ;
			}
		case 3 :
			{
			Zombie *ghost = new Zombie(age,name,message);
			ghost->addsecret();
			smalllist(ghost);
			break;
			}
		case 4 :
			{
			int bone ;
			Skull *ghost = new Skull(age,name,message);
			cout << "How many bones ? : " ;
			cin >> bone ;
			ghost->addbone(bone);
			smalllist(ghost);
			break; 
			}
		case 5 :
			{
			string bandage ;
			Mummy *ghost = new Mummy(age,name,message);
			cout << "Commit on bandage : " ;
			cin.ignore();
			getline(cin,bandage);
			ghost->addbandage(bandage);
			smalllist(ghost);
			break ;
			}
		case 6 :
			{
			string weapon ;
			Dullahan *ghost = new Dullahan(age,name,message);
			cout << "Give a weapon : " ;
			cin.ignore();
			getline(cin,weapon);
			ghost->addweapon(weapon);
			smalllist(ghost);
			break ;
			}
		case 7 :
			{
			string blood ;
			Vampire *ghost = new Vampire(age,name,message);
			cout << "Add blood :" ;
			cin.ignore();
			getline(cin,blood);
			ghost->addblood(blood) ;
			smalllist(ghost);
			break ;
			}
		case 8 :
			{
			string cold ;
			Yuki *ghost = new Yuki(age,name,message);
			cout << "Cold :" ;
			cin.ignore() ;
			getline(cin,cold);
			ghost->addcold(cold);
			smalllist(ghost);
			break ;
			}
		case 9 :
			{
			int foot ;
			string eyes ;
			Kasa *ghost = new Kasa(age,name,message) ;
			cout << "foot number :" ;
			cin >>  foot ;
			cout << "Eyes : " ;
			cin.ignore() ;
			getline(cin,eyes);
			ghost->addinfo(foot,eyes);
			smalllist(ghost);
			break ;
			}
		case 10 :
			{
			string lightsaber ;
			Alan *ghost = new Alan(age,name,message);
			cout << "Your lightsaber : " ;
			cin.ignore();
			getline(cin,lightsaber);
			ghost->addlightsaber(lightsaber);
			smalllist(ghost);
			break ;
			}
		default :
			cout << "\033[31mInvaild choice\033[0m" << endl ;
			return 0 ;
	}

	return 1 ;

};


int rmghost(){
	unsigned int ghostindex ;
	if(ghostlist.size() == 0){
		cout << "\033[31mNo ghost in the party\033[0m " << endl ;
		return 0 ;
	}
	cout << "Choose a ghost which you want to remove from the party : " ;
	cin >> ghostindex ;
	if(ghostindex >= ghostlist.size()){
		cout << "\033[31mInvaild index\033[0m" << endl ;
		return 0 ;
	}
	delete ghostlist[ghostindex];
	ghostlist.erase(ghostlist.begin()+ghostindex);
	return 1;

}

void listghost(){
	vector<Ghost*>::iterator iter;
	int i = 0 ;
	for(iter = ghostlist.begin() ; iter != ghostlist.end() ; iter++,i++){
		cout << i << ". " ;
		cout <<  (**iter).gettype() << " : " << (**iter).getname() << endl;

	}	
	cout << endl ;
}


int showinfo(){
	unsigned int ghostindex ;
	if(ghostlist.size() == 0){
		cout << "\033[31mNo ghost in the party\033[0m " << endl ;
		return 0 ;
	}
	cout << "Choose a ghost which you want to show in the party : " ;
	cin >> ghostindex ;
	if(ghostindex >= ghostlist.size()){
		cout << "\033[31mInvaild index\033[0m" << endl ;
		return 0 ;
	}
	cout << ">-----GHOST INFO-----<" << endl;
	ghostlist[ghostindex]->ghostinfo();
	return 1 ;
}


void sig_alarm_handler(int signum){
	cout << "Connect Timeout" << endl ;
	exit(1);
}

void init(){
	setvbuf(stdout,0,2,0);
	srand(time(NULL));
	signal(SIGALRM,sig_alarm_handler);
	alarm(TIMEOUT);
}


int main(){
	
	unsigned int choice ;
	init();
	while(1){
		menu();
		cout << "Your choice :" ;
		cin >> choice ;
		cout << endl ;
		if(!cin.good()){
			cout << "format error !" << endl;
			exit(0);
		}
		switch(choice){
			case 1 :
				addghost();
				break ;
			case 2 :
				listghost();
				showinfo();
				break ;

			case 3 :
				if(ghostlist.size() == 0){
					cout << "\033[31mNo ghost in the party\033[0m " << endl ;
					break ;
				}
				cout << ">----Night Parade of One Hundred Demons----<" << endl ;
				night();
				cout << ">----Night Parade of One Hundred Demons----<" << endl ;
				break ;
			case 4 :
				listghost();
				rmghost();
				break ;
			case 5 :
				cout << "\033[34mGoodbye\033[0m " << endl ;
				exit(0);
				break ;
			default :
				cout << "\033[31mInvaild choice\033[0m" << endl ;
				break ;


		}

	}

	return 0 ;
}


