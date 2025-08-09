#include "hook/hooks/logger.h"

#include <cstdio>
#include <iostream>
#include <string>

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
