#include <iostream>

#include <windows.h>

int main() {
    auto file = CreateFile("test.txt", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    const char data[] = "sdlfksdjflkdsjfldjk";
    DWORD dwBytesWritten = 0;

    CloseHandle(file);
    system("pause");
    file = CreateFileW(L"text.txt", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        std::cout << "!!! Can't open file (" << GetLastError() << ")\n";
    } else {
        std::cout << "+++ Can open file\n";
    }
    CloseHandle(file);
    file = CreateFileW(L"text.txt", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        std::cout << "!!! Can't open file (" << GetLastError() << ")\n";
    } else {
        std::cout << "+++ Can open file\n";
    }
    return 0;
}
