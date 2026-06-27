#include <iostream>
using namespace std;

int main() {
    int n, W;

    cout << "Enter number of items: ";
    cin >> n;

    int value[n], weight[n];
    double ratio[n];

    cout << "\nEnter value and weight of each item:\n";
    for (int i = 0; i < n; i++) {
        cout << "Item " << i + 1 << " value: ";
        cin >> value[i];
        cout << "Item " << i + 1 << " weight: ";
        cin >> weight[i];
    }

    cout << "\nEnter knapsack capacity: ";
    cin >> W;

    for (int i = 0; i < n; i++) {
        ratio[i] = (double)value[i] / weight[i];
    }

    cout << "\nValue/Weight Ratios:\n";
    for (int i = 0; i < n; i++) {
        cout << "Item " << i + 1 << ": " << ratio[i] << endl;
    }

    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (ratio[j] < ratio[j + 1]) {

                swap(ratio[j], ratio[j + 1]);

                swap(value[j], value[j + 1]);

                swap(weight[j], weight[j + 1]);
            }
        }
    }

    cout << "\nAfter sorting :\n";
    for (int i = 0; i < n; i++) {
        cout << "Value: " << value[i]
             << ", Weight: " << weight[i]
             << ", Ratio: " << ratio[i] << endl;
    }

    double totalValue = 0.0;

    for (int i = 0; i < n; i++) {
        if (W >= weight[i]) {
            cout << "\nTaking full item (Value: " << value[i] << ")";
            totalValue += value[i];
            W -= weight[i];
        } else {
            double fraction = (double)W / weight[i];
            cout << "\nTaking " << fraction * 100 << "% of item (Value: " << value[i] << ")";
            totalValue += value[i] * fraction;
            break;
        }
    }

    cout << "\n\nMaximum value = " << totalValue << endl;

    return 0;
}
