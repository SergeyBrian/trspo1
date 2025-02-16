#include "patch.hpp"

#include <iostream>

HookPatch::HookPatch(const char *lib_name, const char *func_name,
                     const void *hook_func) {
  lib_handle = LoadLibrary(lib_name);
  if (!lib_handle) {
    throw std::exception("[!] Can't find target library");
  }
  address = reinterpret_cast<void *>(GetProcAddress(lib_handle, func_name));
  if (!address) {
    throw std::exception("[!] Can't find target function");
  }

  DWORD tmp{};
  VirtualProtect(reinterpret_cast<LPVOID>(address), 15, PAGE_EXECUTE_READWRITE,
                 &tmp);

  uint8_t data[] = {
      /*
        0:  48 b8 00 00 00 00 00    movabs rax,0x0
        7:  00 00 00
        a:  ff e0                   jmp    rax
      */
      0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0,
  };

  memcpy(old_bytes, reinterpret_cast<uint8_t *>(address), sizeof(data));

  uint64_t offset = reinterpret_cast<uint64_t>(hook_func) -
                    (reinterpret_cast<uint64_t>(address) + 5);
  memcpy(data + 2, &hook_func, sizeof(hook_func));

  memcpy(address, data, sizeof(data));

  std::cout << "[+] Hook added\n";
  VirtualProtect(reinterpret_cast<LPVOID>(address), 10, tmp, &tmp);
}

HookPatch::~HookPatch() {
  std::cout << "[-] Removing hook\n";
  DWORD tmp{};
  VirtualProtect(reinterpret_cast<LPVOID>(address), 15, PAGE_EXECUTE_READWRITE,
                 &tmp);
  memcpy(address, old_bytes, sizeof(old_bytes));
  VirtualProtect(reinterpret_cast<LPVOID>(address), 15, tmp, &tmp);
  std::cout << "[+] Hook removed\n";
}
