#include <cstdio>
#include <stdio.h>

#include <windows.h>

#include "../src/hook_manager.hpp"
#include "../src/hook.hpp"

BOOL __stdcall CloseHook(HANDLE handle) {
  std::printf("[+] Hook called\n");
  return true;
}
BOOL __stdcall WriteHook(_In_ HANDLE hFile,
                         _In_reads_bytes_opt_(nNumberOfBytesToWrite)
                             LPCVOID lpBuffer,
                         _In_ DWORD nNumberOfBytesToWrite,
                         _Out_opt_ LPDWORD lpNumberOfBytesWritten,
                         _Inout_opt_ LPOVERLAPPED lpOverlapped) {
  std::printf("[+] Write hook called (data: %s)\n",
              reinterpret_cast<const char *>(lpBuffer));
  return true;
}

HANDLE
__stdcall CreateFileHook(_In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAccess,
                         _In_ DWORD dwShareMode,
                         _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                         _In_ DWORD dwCreationDisposition,
                         _In_ DWORD dwFlagsAndAttributes,
                         _In_opt_ HANDLE hTemplateFile) {
  std::printf("[+] CreateFile hook called (file %s)\n", lpFileName);
  return nullptr;
}

int main() {
  hook::HookManager manager;

  manager.AddPatch("kernel32.dll", "CreateFileA",
                   reinterpret_cast<void *>(hook::Hook));

  auto file = CreateFile("test.txt", GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  const char data[] = "sdlfksdjflkdsjfldjk";
  DWORD dwBytesWritten = 0;

  int bErrorFlag = WriteFile(file, data, sizeof(data), &dwBytesWritten, NULL);
  CloseHandle(file);
  return 0;
}
