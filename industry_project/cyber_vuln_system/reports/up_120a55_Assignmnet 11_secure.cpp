#include <iostream>
#include <vector>
#include <algorithm>
#include <iomanip>

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

    std::cout << "Enter number of items: ";
    std::cin >> n;

    if (n <= 0) {
        std::cerr << "Error: Number of items must be positive." << std::endl;
        return 1;
    }

    std::vector<Item> items(n);

    std::cout << "\nEnter value and weight of each item:\n";
    for (int i = 0; i < n; ++i) {
        std::cout << "Item " << i + 1 << " value: ";
        std::cin >> items[i].value;
        std::cout << "Item " << i + 1 << " weight: ";
        std::cin >> items[i].weight;

        if (items[i].weight <= 0) {
            std::cerr << "Error: Item weight must be positive." << std::endl;
            return 1;
        }
        items[i].ratio = static_cast<double>(items[i].value) / items[i].weight;
    }

    int W;
    std::cout << "\nEnter knapsack capacity: ";
    std::cin >> W;

    if (W < 0) {
        std::cerr << "Error: Knapsack capacity cannot be negative." << std::endl;
        return 1;
    }

    std::cout << "\nValue/Weight Ratios:\n";
    for (int i = 0; i < n; ++i) {
        std::cout << "Item " << i + 1 << ": " << std::fixed << std::setprecision(2) << items[i].ratio << std::endl;
    }

    std::sort(items.begin(), items.end(), compareItems);

    std::cout << "\nAfter sorting :\n";
    for (int i = 0; i < n; ++i) {
        std::cout << "Value: " << items[i].value
                  << ", Weight: " << items[i].weight
                  << ", Ratio: " << std::fixed << std::setprecision(2) << items[i].ratio << std::endl;
    }

    double totalValue = 0.0;

    for (int i = 0; i < n; ++i) {
        if (W == 0) break;

        if (W >= items[i].weight) {
            std::cout << "\nTaking full item (Value: " << items[i].value << ")";
            totalValue += items[i].value;
            W -= items[i].weight;
        } else {
            double fraction = static_cast<double>(W) / items[i].weight;
            std::cout << "\nTaking " << fraction * 100 << "% of item (Value: " << items[i].value << ")";
            totalValue += items[i].value * fraction;
            W = 0; // Knapsack is full
            break;
        }
    }

    std::cout << "\n\nMaximum value = " << totalValue << std::endl;

    return 0;
}
