#include <stdio.h>

int main() {
    char name[10];

    printf("Enter your name: ");
    gets(name);   // vulnerable function

    printf("Hello %s\n", name);

    return 0;
}