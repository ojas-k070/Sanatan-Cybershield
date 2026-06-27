#include <stdio.h>

int main() {
    char name[10];

    printf("Enter your name: ");
    // Use fgets for safe input, specifying buffer size and reading from stdin
    if (fgets(name, sizeof(name), stdin) != NULL) {
        // Optional: Remove trailing newline character if present
        name[strcspn(name, "\n")] = 0;
        printf("Hello %s\n", name);
    } else {
        printf("Error reading input.\n");
        return 1; // Indicate an error
    }

    return 0;
}