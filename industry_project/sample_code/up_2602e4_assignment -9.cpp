#include <iostream>
#include <string>
using namespace std;

#define SIZE 10

string nameLP[SIZE];
long long phoneLP[SIZE];

struct node
{
    string name;
    long long phone;
    node *next;
};

node *table[SIZE];

int hashFunction(string key)
{
    int sum = 0;
    for(int i=0;i<key.length();i++)
        sum += key[i];

    return sum % SIZE;
}

void insertLP(string name,long long phone)
{
    int index = hashFunction(name);

    while(nameLP[index] != "" && nameLP[index] != "DELETED")
        index = (index + 1) % SIZE;

    nameLP[index] = name;
    phoneLP[index] = phone;
}

void searchLP(string key)
{
    int index = hashFunction(key);
    int i = index;

    while(nameLP[i] != "")
    {
        if(nameLP[i] == key)
        {
            cout<<"Found: "<<phoneLP[i]<<endl;
            return;
        }

        i = (i + 1) % SIZE;
        if(i == index)
            break;
    }

    cout<<"Not Found\n";
}

void deleteLP(string key)
{
    int index = hashFunction(key);
    int i = index;

    while(nameLP[i] != "")
    {
        if(nameLP[i] == key)
        {
            nameLP[i] = "DELETED";
            phoneLP[i] = 0;
            cout<<"Deleted\n";
            return;
        }

        i = (i + 1) % SIZE;
        if(i == index)
            break;
    }

    cout<<"Not Found\n";
}

void displayLP()
{
    cout<<"\nLinear Probing Table\n";

    for(int i=0;i<SIZE;i++)
    {
        cout<<i<<" -> ";
        if(nameLP[i] != "" && nameLP[i] != "DELETED")
            cout<<nameLP[i]<<" "<<phoneLP[i];
        else
            cout<<"Empty";
        cout<<endl;
    }
}

void insertSC(string name,long long phone)
{
    int index = hashFunction(name);

    node *newnode = new node{name, phone, NULL};

    if(table[index] == NULL)
        table[index] = newnode;
    else
    {
        node *temp = table[index];
        while(temp->next != NULL)
            temp = temp->next;

        temp->next = newnode;
    }
}

void searchSC(string key)
{
    int index = hashFunction(key);
    node *temp = table[index];

    while(temp != NULL)
    {
        if(temp->name == key)
        {
            cout<<"Found: "<<temp->phone<<endl;
            return;
        }
        temp = temp->next;
    }

    cout<<"Not Found\n";
}

void deleteSC(string key)
{
    int index = hashFunction(key);

    node *temp = table[index];
    node *prev = NULL;

    while(temp != NULL)
    {
        if(temp->name == key)
        {
            if(prev == NULL)
                table[index] = temp->next;
            else
                prev->next = temp->next;

            delete temp;
            cout<<"Deleted\n";
            return;
        }

        prev = temp;
        temp = temp->next;
    }

    cout<<"Not Found\n";
}

void displaySC()
{
    cout<<"\nSeparate Chaining Table\n";

    for(int i=0;i<SIZE;i++)
    {
        cout<<i<<" -> ";
        node *temp = table[i];

        while(temp != NULL)
        {
            cout<<"("<<temp->name<<","<<temp->phone<<") -> ";
            temp = temp->next;
        }

        cout<<"NULL\n";
    }
}

int main()
{
    int choice, op;
    string name;
    long long phone;

    for(int i=0;i<SIZE;i++)
    {
        nameLP[i] = "";
        phoneLP[i] = 0;
        table[i] = NULL;
    }

    cout<<"Choose Method:\n";
    cout<<"1. Linear Probing\n2. Separate Chaining\n";
    cin>>choice;

    do
    {
        cout<<"\n--- MENU ---\n";
        cout<<"1. Insert\n2. Search\n3. Delete\n4. Display\n5. Exit\n";
        cout<<"Enter choice: ";
        cin>>op;

        if(choice == 1)
        {
            switch(op)
            {
                case 1:
                    cout<<"Enter Name & Phone: ";
                    cin>>name>>phone;
                    insertLP(name,phone);
                    break;

                case 2:
                    cout<<"Enter Name: ";
                    cin>>name;
                    searchLP(name);
                    break;

                case 3:
                    cout<<"Enter Name: ";
                    cin>>name;
                    deleteLP(name);
                    break;

                case 4:
                    displayLP();
                    break;
            }
        }
        else if(choice == 2)
        {
            switch(op)
            {
                case 1:
                    cout<<"Enter Name & Phone: ";
                    cin>>name>>phone;
                    insertSC(name,phone);
                    break;

                case 2:
                    cout<<"Enter Name: ";
                    cin>>name;
                    searchSC(name);
                    break;

                case 3:
                    cout<<"Enter Name: ";
                    cin>>name;
                    deleteSC(name);
                    break;

                case 4:
                    displaySC();
                    break;
            }
        }

    } while(op != 5);

    return 0;
}
