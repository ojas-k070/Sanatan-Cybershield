#include <stdio.h>
#include <string.h>

int main() {
    char name[50];

    printf("Enter your name: ");

    if (fgets(name, sizeof(name), stdin) != NULL) {

        // Remove newline safely
        name[strcspn(name, "\n")] = '\0';

        printf("Hello, %s\n", name);
    } else {
        printf("Input error.\n");
    }

    return 0;
}