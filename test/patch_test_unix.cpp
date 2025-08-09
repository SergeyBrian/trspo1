#include "hook/hooks/logger.h"

#include <cstdio>
#include <iostream>
#include <string>
#include <fstream>

#include "hook/manager/manager.h"
#include "hook/hooks/filter.h"

int main() {
    auto mngr = HookManager::Instance();

    hooks::filter::SetHideStrig("test.txt");

    mngr->add_patch("libc.so.6", "fopen", hooks::filter::fopen());

    FILE *f = fopen("test.txt", "w");

    if (!f) {
        std::cout << "!!! Can't open file!\n";
    } else {
        std::cout << "+++ Can open file!\n";
        fclose(f);
    }

    std::ifstream file("test.txt");
    if (file.is_open()) {
        std::cout << "+++ ifstream open worked\n";
        file.close();
    } else {
        std::cout << "!!! ifstream open dont't worked\n";
    }

    mngr->remove_patch("fopen");

    f = fopen("test.txt", "w");
    if (!f) {
        std::cout << "!!! Can't open file!\n";
    } else {
        std::cout << "+++ Can open file!\n";
        fclose(f);
    }

    return 0;
}
