#include <cstdlib>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>

int main(int argc, char **argv) {
  uint64_t pid = std::atoi(argv[1]);
  const char *dll_name = argv[2];

  HANDLE proc =
      OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                      PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                  false, pid);
  if (!proc) {
    std::cout << "Failed to open proccess with pid " << pid << "\n";
    std::cout << GetLastError() << "\n";
    return 1;
  }

  auto new_mem = VirtualAllocEx(proc, nullptr, strlen(dll_name) + 1, MEM_COMMIT,
                                PAGE_READWRITE);
  if (!new_mem) {
    std::cout << "Failed to allocate memory :(\n" << GetLastError() << "\n";
    return 1;
  }

  SIZE_T tmp{};
  if (!WriteProcessMemory(proc, new_mem, dll_name, strlen(dll_name) + 1,
                          &tmp)) {
    std::cout << "Failed to write memory\n" << GetLastError() << "\n";
    return 1;
  }

  std::cout << dll_name << "\n";

  LPVOID loadLibrary =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
  if (!loadLibrary) {
    std::cout << "GetProcAddress failed\n" << GetLastError() << "\n";
    return 1;
  }
  auto thread = CreateRemoteThread(
      proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary),
      new_mem, 0, nullptr);
  if (!thread) {
    std::cout << "Failed to create thread\n" << GetLastError() << "\n";
    return 1;
  }

  std::cout << "Success\n";

  WaitForSingleObject(thread, INFINITE);

  return 0;
}
