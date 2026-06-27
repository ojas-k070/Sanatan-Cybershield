#include <iostream>
#include <cstring>

void vulnerableFunction(char* userInput) {
    // Allocate a small buffer of 10 bytes
    char buffer[10]; 
    
    // VULNERABILITY: strcpy does not check the size of the source string
    std::strcpy(buffer, userInput); 
    
    std::cout << "Buffer contains: " << buffer << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <input_string>" << std::endl;
        return 1;
    }

    vulnerableFunction(argv[1]);
    return 0;
}