#include <iostream>

__attribute__((constructor)) void on_load() { std::cout << "[+] .so loaded\n"; }

__attribute__((destructor)) void on_unload() {
    std::cout << "[-] .so unloaded\n";
}
