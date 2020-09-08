// g++ -s -pie -z relro -z now car_store.cpp -o car_store
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

using namespace std;

class Car
{
public:
    Car()
    {
        amount++;
    };
    ~Car()
    {
        amount--;
    }
    void virtual print()
    {
        cout << "start Car" << endl;
    }

    void show()
    {
        cout << "condition: " << condition << endl;
        cout << "amount: " << amount << endl;
        cout << "price: " << price << endl;
        cout << "name: " << name << endl;
    }

    bool is_empty()
    {
        if (condition == 100)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    bool is_selled()
    {
        if (condition == 101)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    bool is_showed()
    {
        if (condition == 102)
        {
            condition = 103;
            return true;
        }
        else
        {
            return false;
        }
    }

    size_t get_price()
    {
        return this->price;
    }
    string get_name()
    {
        return this->name;
    }

    void set_condition(int con)
    {
        condition = con;
    }

protected:
    void set_price(size_t price)
    {
        this->price = price;
    }

    void set_name(string name)
    {
        this->name = name;
    }

private:
    int condition = 100;
    int amount = 0;
    size_t price;
    string name;
};

class SmallCar : public Car
{
public:
    void print()
    {
        cout << "This is Small Car" << endl;
    }

    void set()
    {
        size_t price;
        string name;
        cout << "price: ";
        cin >> price;
        set_price(price);
        cout << "name: ";
        cin >> name;
        set_name(name);
        cout << "remark: ";
        cin >> SmallCarRemark;
        cout << "success!" << endl;
    }

    string get_remark()
    {
        return this->SmallCarRemark;
    }

private:
    string SmallCarRemark;
};

class BigCar : public Car
{
public:
    void print()
    {
        cout << "This is Big Car, and you can add some gasoline for sale." << endl;
    }

    void set()
    {
        size_t price;
        string name;
        cout << "price: ";
        cin >> price;
        set_price(price);
        cout << "name: ";
        cin >> name;
        set_name(name);
        cout << "remark: ";
        cin >> BigCarRemark;
        cout << "gasoline: ";
        cin >> gasoline;
        cout << "success!" << endl;
    }

    string get_remark()
    {
        return this->BigCarRemark;
    }

private:
    size_t gasoline;
    string BigCarRemark;
};

class Store
{
public:
    void menu()
    {
        cout << "1. build car" << endl;
        cout << "2. sell car" << endl;
        cout << "3. show car" << endl;
        cout << "4. exit" << endl;
        cout << "your choice: ";
    }

    void show_car()
    {
        Car *car;
        int choice;
        unsigned int index;
        cout << endl;
        cout << "1. Small Car" << endl;
        cout << "2. Big Car" << endl;
        cout << "your choice: ";
        cin >> choice;

        if (choice == 1)
        {
            car = (Car *)small_car;
        }
        else if (choice == 2)
        {
            car = (Car *)big_car;
        }
        else
        {
            cout << "Invalid choice!" << endl;
            return;
        }

        cout << "Which car do you want to show: ";
        cin >> index;
        index %= 0x10;

        if (car[index].is_selled())
        {
            car[index].print();
            car[index].show();
            cout << "success!" << endl;
        }
        else if (car[index].is_showed())
        {
            car[index].show();
            cout << "success!" << endl;
        }
        else
        {
            cout << "Error!" << endl;
        }
    }

    void sell_car()
    {
        int choice;
        unsigned int index;
        cout << endl;
        cout << "1. Small Car" << endl;
        cout << "2. Big Car" << endl;
        cout << "your choice: ";
        cin >> choice;

        if (choice == 1)
        {
            cout << "Which car do you want to sell: ";
            cin >> index;
            index %= 0x10;
            if (small_car[index].is_selled())
            {
                small_car[index].print();
                small_car[index].set_condition(102);
                cout << "success!" << endl;
            }
            else
            {
                cout << "Error!" << endl;
            }
        }
        else if (choice == 2)
        {
            cout << "Which car do you want to sell: ";
            cin >> index;
            index %= 0x10;
            if (big_car[index].is_selled())
            {
                big_car[index].print();
                big_car[index].set_condition(102);
                cout << "success!" << endl;
            }
            else
            {
                cout << "Error!" << endl;
            }
        }
        else
        {
            cout << "Invalid choice!" << endl;
        }

        cout << endl;
    }

    void build_car()
    {
        int choice;
        cout << endl;
        cout << "1. Small Car" << endl;
        cout << "2. Big Car" << endl;
        cout << "your choice: ";
        cin >> choice;

        if (choice == 1)
        {
            int i;
            for (i = 0; i < 0x10; i++)
            {
                if (small_car[i].is_empty())
                {
                    break;
                }
            }

            if (i == 0x10)
            {
                cout << "Sorry, there is no space." << endl;
            }
            else
            {
                small_car[i].print();
                small_car[i].set();

                small_car[i].set_condition(101);
            }
        }
        else if (choice == 2)
        {
            int i;
            for (i = 0; i < 0x10; i++)
            {
                if (big_car[i].is_empty())
                {
                    break;
                }
            }

            if (i == 0x10)
            {
                cout << "Sorry, there is no space." << endl;
            }
            else
            {
                big_car[i].print();
                big_car[i].set();
                big_car[i].set_condition(101);
            }
        }
        else
        {
            cout << "Invalid choice!" << endl;
        }

        cout << endl;
    }

private:
    BigCar big_car[0x10];
    SmallCar small_car[0x10];
};

int main()
{
    Store *store = new Store();
    int choice = 0;

    alarm(60);
    setbuf(stdout, NULL);

    cout << "Welcome to Car Store!" << endl;

    while (choice != 4)
    {
        store->menu();
        cin >> choice;

        switch (choice)
        {
        case 1:
            store->build_car();
            break;
        case 2:
            store->sell_car();
            break;
        case 3:
            store->show_car();
            break;
        case 4:
            break;
        default:
            cout << "Invalid choice!" << endl
                 << endl;
            break;
        }

        cout << endl;
    }

    return 0;
}