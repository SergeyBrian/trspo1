#include <cstdio>
#include <stdio.h>

#include <windows.h>

int main() {
    auto file = CreateFile("test.txt", GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    const char data[] = "sdlfksdjflkdsjfldjk";
    DWORD dwBytesWritten = 0;

    int bErrorFlag = WriteFile(file, data, sizeof(data), &dwBytesWritten, NULL);
    CloseHandle(file);
    while (true);
    return 0;
}
