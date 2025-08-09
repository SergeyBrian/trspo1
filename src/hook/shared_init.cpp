#include <unistd.h>
#include <iostream>
#include <thread>

#include "setup.h"

__attribute__((constructor)) void on_load() {
    std::cout << "[+] .so loaded\n";
    std::thread t([] { setup(); });
    t.detach();
}

__attribute__((destructor)) void on_unload() {
    std::cout << "[-] .so unloaded\n";
}
