#include <iostream>
#include <vector>
#include <algorithm>

struct Item {
    int value;
    int weight;
    double ratio;
};

bool compareItems(const Item& a, const Item& b) {
    return a.ratio > b.ratio;
}

int main() {
    int n;
    double W;

    std::cout << "Enter number of items: ";
    std::cin >> n;

    std::vector<Item> items(n);

    std::cout << "\nEnter value and weight of each item:\n";
    for (int i = 0; i < n; ++i) {
        std::cout << "Item " << i + 1 << " value: ";
        std::cin >> items[i].value;
        std::cout << "Item " << i + 1 << " weight: ";
        std::cin >> items[i].weight;
        if (items[i].weight > 0) {
            items[i].ratio = static_cast<double>(items[i].value) / items[i].weight;
        } else {
            items[i].ratio = 0.0; // Handle division by zero, though weight should ideally be positive
        }
    }

    std::cout << "\nEnter knapsack capacity: ";
    std::cin >> W;

    std::sort(items.begin(), items.end(), compareItems);

    std::cout << "\nAfter sorting :\n";
    for (int i = 0; i < n; ++i) {
        std::cout << "Value: " << items[i].value
                  << ", Weight: " << items[i].weight
                  << ", Ratio: " << items[i].ratio << std::endl;
    }

    double totalValue = 0.0;

    for (int i = 0; i < n; ++i) {
        if (W <= 0) break; // Knapsack is full

        if (items[i].weight <= W) {
            std::cout << "\nTaking full item (Value: " << items[i].value << ")";
            totalValue += items[i].value;
            W -= items[i].weight;
        } else {
            double fraction = W / static_cast<double>(items[i].weight);
            std::cout << "\nTaking " << fraction * 100 << "% of item (Value: " << items[i].value << ")";
            totalValue += items[i].value * fraction;
            W = 0; // Knapsack is now full
            break;
        }
    }

    std::cout << "\n\nMaximum value = " << totalValue << std::endl;

    return 0;
}
