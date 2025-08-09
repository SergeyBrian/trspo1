#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "setup.h"

DWORD WINAPI Main(LPVOID) {
    setup();
    Sleep(INFINITE);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, Main, NULL, 0, NULL);
    }
    return TRUE;
}
