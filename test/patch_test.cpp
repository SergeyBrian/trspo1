#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>

#include "hook/manager/manager.h"
#include "hook/hooks/filter.h"

void __stdcall hook_func() { std::cout << "hook called\n"; }

int main() {
    auto mngr = HookManager::Instance();
    std::cout << "hook_func: " << std::hex
              << reinterpret_cast<void *>(&hook_func) << "\n"
              << std::dec;

    hooks::filter::SetHideStrig("test.txt");
    mngr->add_patch("kernel32.dll", "CreateFileA",
                    reinterpret_cast<void *>(hooks::filter::CreateFileA()));
    mngr->add_patch("kernel32.dll", "WriteFile",
                    reinterpret_cast<void *>(&hook_func));

    auto file = CreateFile("test.txt", GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!file) {
        std::cout << "[!!!] CreateFileA failed (as test case)";
        return 0;
    }

    const char data[] = "sdlfksdjflkdsjfldjk";
    DWORD dwBytesWritten = 0;

    WriteFile(file, data, sizeof(data), &dwBytesWritten, NULL);
    mngr->remove_patch("WriteFile");
    WriteFile(file, data, sizeof(data), &dwBytesWritten, NULL);

    CloseHandle(file);
}
