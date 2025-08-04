#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>

#include "hook/manager/manager.h"

void __stdcall hook_func() { std::cout << "hook called\n"; }

int main() {
    auto mngr = HookManager::Instance();
    std::cout << "hook_func: " << std::hex
              << reinterpret_cast<void *>(&hook_func) << "\n"
              << std::dec;

    mngr->AddPatch("kernel32.dll", "CreateFileA",
                   reinterpret_cast<void *>(&hook_func));
    mngr->AddPatch("kernel32.dll", "WriteFile",
                   reinterpret_cast<void *>(&hook_func));

    auto file = CreateFile("test.txt", GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);

    const char data[] = "sdlfksdjflkdsjfldjk";
    DWORD dwBytesWritten = 0;

    WriteFile(file, data, sizeof(data), &dwBytesWritten, NULL);
    mngr->RemovePatch("WriteFile");
    WriteFile(file, data, sizeof(data), &dwBytesWritten, NULL);

    CloseHandle(file);
}
