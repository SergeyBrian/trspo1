#include <dlfcn.h>
#include <unistd.h>
#include <fstream>
#include <iostream>

int main() {
    std::cout << "test\n";
    std::cout << getpid() << "\n";
    std::ofstream file{};
    file.open("test.txt");

    std::cout << std::hex;
    std::cout << "malloc_ptr: " << reinterpret_cast<uint64_t>(&malloc) << "\n";
    std::cout << "free_ptr: " << reinterpret_cast<uint64_t>(&free) << "\n";
    std::cout << "dlopen_ptr: " << reinterpret_cast<uint64_t>(&dlopen) << "\n";
    std::cout << std::dec;

    file.close();

    getchar();

    file.open("test.txt");
    if (!file.is_open()) {
        std::cout << "!!! Can't open file\n";
    } else {
        std::cout << "+++ Can open file\n";
    }
    file.close();
    file.open("test.txt");

    return 0;
}
