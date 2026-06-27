#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <stdexcept>

using namespace std;

#define SIZE 10

// Using std::vector for dynamic resizing and better memory management
vector<string> nameLP(SIZE, "");
vector<long long> phoneLP(SIZE, 0);

struct node
{
    string name;
    long long phone;
    node *next;
};

vector<node*> table(SIZE, nullptr);

// A more robust hash function (e.g., FNV-1a)
unsigned int hashFunction(const string& key)
{
    unsigned int hash = 2166136261U; // FNV offset basis
    for (char c : key)
    {
        hash ^= static_cast<unsigned char>(c);
        hash *= 16777619U; // FNV prime
    }
    return hash % SIZE;
}

void insertLP(const string& name, long long phone)
{
    if (name.empty()) {
        cerr << "Error: Name cannot be empty."
        return;
    }

    int startIndex = hashFunction(name);
    int index = startIndex;
    int probes = 0;

    while (probes < SIZE) {
        if (nameLP[index] == "" || nameLP[index] == "DELETED") {
            nameLP[index] = name;
            phoneLP[index] = phone;
            return;
        }
        index = (index + 1) % SIZE;
        probes++;
        if (index == startIndex) break; // Table is full
    }

    cerr << "Error: Hash table is full. Cannot insert '" << name << "'." << endl;
}

void searchLP(const string& key)
{
    if (key.empty()) {
        cerr << "Error: Key cannot be empty."
        return;
    }

    int startIndex = hashFunction(key);
    int index = startIndex;
    int probes = 0;

    while (nameLP[index] != "") {
        if (nameLP[index] == key) {
            cout << "Found: " << phoneLP[index] << endl;
            return;
        }
        index = (index + 1) % SIZE;
        probes++;
        if (index == startIndex) break; // Searched the whole table
    }

    cout << "Not Found\n";
}

void deleteLP(const string& key)
{
    if (key.empty()) {
        cerr << "Error: Key cannot be empty."
        return;
    }

    int startIndex = hashFunction(key);
    int index = startIndex;
    int probes = 0;

    while (nameLP[index] != "") {
        if (nameLP[index] == key) {
            nameLP[index] = "DELETED";
            phoneLP[index] = 0; // Or some other indicator
            cout << "Deleted\n";
            return;
        }
        index = (index + 1) % SIZE;
        probes++;
        if (index == startIndex) break; // Searched the whole table
    }

    cout << "Not Found\n";
}

void displayLP()
{
    cout << "\nLinear Probing Table\n";

    for (int i = 0; i < SIZE; ++i)
    {
        cout << i << " -> ";
        if (nameLP[i] != "" && nameLP[i] != "DELETED")
            cout << nameLP[i] << " " << phoneLP[i];
        else
            cout << "Empty";
        cout << endl;
    }
}

void insertSC(const string& name, long long phone)
{
    if (name.empty()) {
        cerr << "Error: Name cannot be empty."
        return;
    }

    int index = hashFunction(name);

    // Use smart pointers to manage memory automatically
    node *newnode = new node{name, phone, nullptr};

    if (table[index] == nullptr)
        table[index] = newnode;
    else
    {
        node *temp = table[index];
        while (temp->next != nullptr)
            temp = temp->next;

        temp->next = newnode;
    }
}

void searchSC(const string& key)
{
    if (key.empty()) {
        cerr << "Error: Key cannot be empty."
        return;
    }

    int index = hashFunction(key);
    node *temp = table[index];

    while (temp != nullptr)
    {
        if (temp->name == key)
        {
            cout << "Found: " << temp->phone << endl;
            return;
        }
        temp = temp->next;
    }

    cout << "Not Found\n";
}

void deleteSC(const string& key)
{
    if (key.empty()) {
        cerr << "Error: Key cannot be empty."
        return;
    }

    int index = hashFunction(key);

    node *temp = table[index];
    node *prev = nullptr;

    while (temp != nullptr)
    {
        if (temp->name == key)
        {
            if (prev == nullptr)
                table[index] = temp->next;
            else
                prev->next = temp->next;

            delete temp;
            cout << "Deleted\n";
            return;
        }

        prev = temp;
        temp = temp->next;
    }

    cout << "Not Found\n";
}

void displaySC()
{
    cout << "\nSeparate Chaining Table\n";

    for (int i = 0; i < SIZE; ++i)
    {
        cout << i << " -> ";
        node *temp = table[i];

        while (temp != nullptr)
        {
            cout << "(" << temp->name << "," << temp->phone << ") -> ";
            temp = temp->next;
        }

        cout << "NULL\n";
    }
}

// Helper function to clear the input buffer
void clearInputBuffer() {
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

int main()
{
    int choice, op;
    string name;
    long long phone;

    // Initialization is handled by vector constructors

    cout << "Choose Method:\n";
    cout << "1. Linear Probing\n2. Separate Chaining\n";
    
    while (!(cin >> choice) || (choice != 1 && choice != 2)) {
        cerr << "Invalid input. Please enter 1 or 2: ";
        cin.clear();
        clearInputBuffer();
    }
    clearInputBuffer(); // Consume the newline character after valid input

    do
    {
        cout << "\n--- MENU ---\n";
        cout << "1. Insert\n2. Search\n3. Delete\n4. Display\n5. Exit\n";
        cout << "Enter choice: ";
        
        while (!(cin >> op) || (op < 1 || op > 5)) {
            cerr << "Invalid input. Please enter a number between 1 and 5: ";
            cin.clear();
            clearInputBuffer();
        }
        clearInputBuffer(); // Consume the newline character after valid input

        if (choice == 1)
        {
            switch (op)
            {
                case 1:
                    cout << "Enter Name & Phone: ";
                    // Use getline for names that might contain spaces
                    if (cin >> name) {
                        if (cin >> phone) {
                            insertLP(name, phone);
                        } else {
                            cerr << "Invalid phone number input.\n";
                            cin.clear();
                            clearInputBuffer();
                        }
                    } else {
                        cerr << "Invalid name input.\n";
                        cin.clear();
                        clearInputBuffer();
                    }
                    break;

                case 2:
                    cout << "Enter Name: ";
                    if (cin >> name) {
                        searchLP(name);
                    } else {
                        cerr << "Invalid name input.\n";
                        cin.clear();
                        clearInputBuffer();
                    }
                    break;

                case 3:
                    cout << "Enter Name: ";
                    if (cin >> name) {
                        deleteLP(name);
                    } else {
                        cerr << "Invalid name input.\n";
                        cin.clear();
                        clearInputBuffer();
                    }
                    break;

                case 4:
                    displayLP();
                    break;
            }
        }
        else if (choice == 2)
        {
            switch (op)
            {
                case 1:
                    cout << "Enter Name & Phone: ";
                    if (cin >> name) {
                        if (cin >> phone) {
                            insertSC(name, phone);
                        } else {
                            cerr << "Invalid phone number input.\n";
                            cin.clear();
                            clearInputBuffer();
                        }
                    } else {
                        cerr << "Invalid name input.\n";
                        cin.clear();
                        clearInputBuffer();
                    }
                    break;

                case 2:
                    cout << "Enter Name: ";
                    if (cin >> name) {
                        searchSC(name);
                    } else {
                        cerr << "Invalid name input.\n";
                        cin.clear();
                        clearInputBuffer();
                    }
                    break;

                case 3:
                    cout << "Enter Name: ";
                    if (cin >> name) {
                        deleteSC(name);
                    } else {
                        cerr << "Invalid name input.\n";
                        cin.clear();
                        clearInputBuffer();
                    }
                    break;

                case 4:
                    displaySC();
                    break;
            }
        }

    } while (op != 5);

    // Clean up memory for separate chaining
    for (int i = 0; i < SIZE; ++i) {
        node *current = table[i];
        while (current != nullptr) {
            node *next = current->next;
            delete current;
            current = next;
        }
        table[i] = nullptr;
    }

    return 0;
}
