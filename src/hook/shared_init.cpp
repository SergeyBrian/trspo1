#include <unistd.h>
#include <iostream>

/*#include "setup.h"*/

__attribute__((constructor)) void on_load() {
    std::cout << "[+] .so loaded\n";
    /*setup();*/
    sleep(-1);
}

__attribute__((destructor)) void on_unload() {
    std::cout << "[-] .so unloaded\n";
}
