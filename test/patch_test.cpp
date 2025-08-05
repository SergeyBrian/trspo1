#include "hook/hooks/logger.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>
#include <string>

#include "hook/manager/manager.h"
#include "hook/hooks/filter.h"

int main() {
    auto mngr = HookManager::Instance();

    hooks::filter::SetHideStrig("test.txt");
    mngr->add_patch("kernel32.dll", "CreateFileA",
                    hooks::filter::CreateFileA());
    mngr->add_patch("kernel32.dll", "WriteFile",
                    hooks::logger::Logger("WriteFile"));

    auto file = CreateFile("text.txt", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        std::cout << "[!!!] CreateFileA failed (as test case) ("
                  << GetLastError() << ")\n";
        return 0;
    }
    std::cout << "[+++] CreateFileA succeeded (as test case)\n";

    const char data[] = "test text\n";
    DWORD dwBytesWritten = 0;

    WriteFile(file, data, sizeof(data), &dwBytesWritten, NULL);
    mngr->remove_patch("WriteFile");
    WriteFile(file, data, sizeof(data), &dwBytesWritten, NULL);

    CloseHandle(file);
}
