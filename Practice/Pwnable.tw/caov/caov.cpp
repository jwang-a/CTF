/* g++ -std=c++11 -Wl,-z,relro,-z,now -o caov caov.cpp */

#include <bits/stdc++.h>
#include <unistd.h>

using namespace std;

class Data;

Data *D;
char name[160];

class Data
{
    public:
        Data():key(NULL) , value(0), change_count(0){ init_time(); }
        Data(string k, int v)
        {
            key = new char[k.length() + 1];
            strcpy(key, k.c_str());
            value = v;
            change_count = 0;
            update_time();
        }
        Data(const Data &obj)
        {
            key = new char[strlen(obj.key)+1];
            strcpy(key, obj.key);
            value = obj.value;
            change_count = obj.change_count;
            year  = obj.year;
            month = obj.month;
            day   = obj.day;
            hour  = obj.hour;
            min   = obj.min;
            sec   = obj.sec;
        }
        Data operator=(const Data &rhs)
        {
            key = new char[strlen(rhs.key)+1];
            strcpy(key, rhs.key);
            value = rhs.value;
            change_count = rhs.change_count;
            year  = rhs.year;
            month = rhs.month;
            day   = rhs.day;
            hour  = rhs.hour;
            min   = rhs.min;
            sec   = rhs.sec;
        }
        void edit_data()
        {
            if(change_count == 10)
            {
                cout << "You can only edit your data 10 times at most." << endl;
                cout << "Bye ._.\\~/" << endl;
                exit(0);
            }
            int old_len = strlen(key);
            unsigned int new_len = 0;
            cout << "New key length: ";
            cin  >> new_len;
            getchar();
            if(new_len == 0 || new_len > 1000)
            {
                cout << "Invalid key length" << endl;
                return;
            }
            if (new_len > old_len) key = new char[new_len+1];
            set_data(new_len);
            change_count += 1;
        }   
        void set_data(unsigned int n)
        {
            cout << "Key: ";
            cin.getline(key, n+1); // read n byte + 1 null byte ( auto append )
            cout << "Value: ";
            cin >> value;
            getchar();
            update_time();
        }
        void update_time()
        {
            time_t cur_time = time(NULL);
            struct tm *now = localtime(&cur_time);
            year = now->tm_year + 1900;
            month = now->tm_mon + 1;
            day = now->tm_mday;
            hour = now->tm_hour;
            min = now->tm_min;
            sec = now->tm_sec;
        }
        void info()
        {
            cout << "Key: " << key << endl;
            cout << "Value: " << value << endl;
            cout << "Edit count: " << change_count << endl;
            cout << "Last update time: ";
            printf("%d-%d-%d %d:%d:%d\n", year, month, day, hour, min, sec);
        }
        ~Data()
        {
            delete[] key;
            key = nullptr;
            value = 0;
            change_count = 0;
            init_time();
        }

    private:
        char *key;
        long value;
        long change_count;
        int year;
        int month;
        int day;
        int hour;
        int min;
        int sec;
        void init_time()
        {
            year  = 0;
            month = 0;
            day   = 0;
            hour  = 0;
            min   = 0;
            sec   = 0;
        }
};

void set_name()
{
    char tmp[160]={};
    char c;
    cout << "Enter your name: ";
    int cnt = 0;
    while(1)
    {
        int len = read(0, &c, 1);
        if(len != 1)
        {
            cout << "Read error" << endl;
            exit(-1);
        }
        tmp[cnt++] = c;
        if(c == '\n' || cnt == 150)
        {
            tmp[cnt-1] = '\0';
            break;            
        }
    }
    memcpy(name, tmp, cnt);
}

void edit()
{
    Data old;
    old = *D;
    D->edit_data();
    cout << "\nYour data info before editing:" << endl;
    old.info();
    cout << "\nYour data info after editing:" << endl;
    D->info();
}

void playground()
{
    int choice = 0;
    while(1)
    {
        cout << "\nMenu" << endl;
        cout << "1. Show name & data" << endl;
        cout << "2. Edit name & data" << endl;
        cout << "3. Exit" << endl;
        cout << "Your choice: ";
        cin >> choice;
        getchar();
        switch(choice)
        {
            case 1:
                cout << "\nYour name is : "<< name << endl;
                cout << "Your data :" << endl;
                D->info();
                break;
            case 2:
                set_name();
                edit();
                break;
            case 3:
                cout << "Bye !" << endl;
                return;
            default:
                cout << "Invalid choice !" << endl;
                exit(0);
        }
    }
}

int main(int argc, char *argv[])
{  
    setvbuf(stdin,0, 2, 0);
    setvbuf(stdout,0, 2, 0);
    setvbuf(stderr,0, 2, 0);

    string k;
    long v;

    set_name();
    cout << "Hello ! " << name << " !" << endl;
    cout << "Welcome to Simple key-value DB playground !" << endl;
    cout << "Please input a key: ";
    cin >> k;
    cout << "Please input a value: ";
    cin >> v;

    D = new Data(k, v);
    cout << "Data create success !" << endl;
    cout << "Now you can play with your data ^_^" << endl;

    playground();

    return 0;
}
