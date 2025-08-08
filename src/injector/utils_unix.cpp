#include "utils.h"

#include <cstdio>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

#include <capstone/capstone.h>

void soloader() {
    // rax -> malloc_ptr
    // rbx -> free_ptr
    // rdx -> dlopen_ptr
    asm(
        // Fix stack alignment
        "mov %rsp, %r9\n"
        "and $~0xF, %r9\n"
        "sub $8, %r9\n"
        "mov %r9, %rsp\n"

        // free
        "push %rbx\n"
        // dlopen
        "push %rdx\n"

        // Alloc space for lib path
        "mov %rax, %r9\n"       // malloc_ptr
        "movabs $0xCE, %rdi\n"  // MAX_PATH

        "callq *%r9\n"

        "int $3\n"  // rax -> lib name ptr

        // Call to dlopen
        "pop %r9\n"          // dlopen
        "mov %rax, %rdi\n"   // lib name ptr
        "movabs $1, %rsi\n"  // RTLD_LAZY

        "callq *%r9\n"

        "int $3\n"

    );
}
void soloader_end() {}

user_regs_struct get_regs(pid_t pid) {
    user_regs_struct regs;
    std::memset(&regs, 0, sizeof(regs));

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        std::cout << "[!] PTRACE_GETREGS failed\n";
        return {};
    }
    return regs;
}

bool set_regs(pid_t pid, user_regs_struct regs) {
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        std::cout << "[!] PTRACE_SETREGS failed\n";
        return false;
    }
    return true;
}

bool check_cmdline(pid_t pid, const std::string &name) {
    std::ifstream cmdline("/proc/" + std::to_string(pid) + "/cmdline");
    std::string content;
    std::getline(cmdline, content, '\0');
    return content.find(name) != std::string::npos;
}

uint64_t get_pid_by_name(const char *name) {
    for (const auto &entry : std::filesystem::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;

        const std::string pid_str = entry.path().filename();
        if (!std::all_of(pid_str.begin(), pid_str.end(), ::isdigit)) continue;

        pid_t pid = std::stoi(pid_str);

        if (check_cmdline(pid, name)) {
            return pid;
        }
    }

    return 0;
}

std::string get_full_path(const std::string &base) {
    const char *res = realpath(base.c_str(), nullptr);
    if (!res) {
        std::cout << "[!] realpath failed\n";
        return {};
    }
    return res;
}

static std::string strip_deleted(const std::string &s) {
    const std::string suffix = " (deleted)";
    if (s.size() >= suffix.size() &&
        s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0)
        return s.substr(0, s.size() - suffix.size());
    return s;
}

static std::string basename_only(const char *path) {
    if (!path) return {};
    const char *p = strrchr(path, '/');
    return std::string(p ? p + 1 : path);
}

static uint64_t get_module_base_by_basename(
    pid_t pid, const std::string &soname_basename) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps.is_open()) return 0;

    uint64_t base = 0;
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream iss(line);
        std::string addr_range, perms, offset, dev, inode, path;
        if (!(iss >> addr_range >> perms >> offset >> dev >> inode)) continue;
        std::getline(iss, path);
        if (!path.empty() && path[0] == ' ') path.erase(0, 1);
        if (path.empty()) continue;

        path = strip_deleted(path);
        std::string base_name = basename_only(path.c_str());

        if (base_name == soname_basename) {
            auto dash = addr_range.find('-');
            if (dash == std::string::npos) continue;
            uint64_t start =
                std::stoull(addr_range.substr(0, dash), nullptr, 16);
            if (base == 0 || start < base) base = start;
        }
    }
    return base;
}

uint64_t get_func(pid_t pid, const std::string &symbol) {
    void *h = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
    if (!h) {
        fprintf(stderr, "[!] dlopen libc failed\n");
        return 0;
    }

    void *sym = dlsym(h, symbol.c_str());
    if (!sym) {
        fprintf(stderr, "[!] dlsym failed (%s)\n", symbol.c_str());
        return 0;
    }

    Dl_info info{};
    if (!dladdr(sym, &info) || !info.dli_fbase || !info.dli_fname) {
        fprintf(stderr, "[!] dladdr failed (%s)\n", symbol.c_str());
        return 0;
    }

    uint64_t local_base = reinterpret_cast<uint64_t>(info.dli_fbase);
    uint64_t local_addr = reinterpret_cast<uint64_t>(sym);
    uint64_t offset = local_addr - local_base;

    std::string soname = basename_only(info.dli_fname);

    uint64_t remote_base = get_module_base_by_basename(pid, soname);
    if (!remote_base) {
        fprintf(stderr, "[!] remote libc base not found for %s in pid %d\n",
                soname.c_str(), pid);
        return 0;
    }

    return remote_base + offset;
}

uint64_t get_libc_addr(int64_t pid) {
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps(maps_path);
    std::string line;
    uint64_t libc_base = 0;
    while (getline(maps, line)) {
        if (line.find("libc") != std::string::npos &&
            line.find("r-xp") != std::string::npos) {
            libc_base = stoull(line.substr(0, line.find('-')), nullptr, 16);
            break;
        }
    }
    maps.close();
    if (!libc_base) {
        std::cout << "[!] Failed to find libc base\n";
        return 0;
    }
    return libc_base;
}

uint64_t find_xmem(int64_t pid) {
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps(maps_path);
    std::string line;
    uint64_t addr = 0;
    char perms[5];
    char _[20];
    while (getline(maps, line)) {
        std::sscanf(line.c_str(), "%lx-%*lx %s %*s %s %*d", &addr, perms, _);
        std::cout << line << "\n";

        if (strstr(perms, "x") != NULL) {
            break;
        }
    }
    maps.close();
    return addr;
}

bool ptrace_read(int64_t pid, void *addr, void *vptr, size_t len) {
    int bytesRead = 0;
    int i = 0;
    long word = 0;
    long *ptr = (long *)vptr;

    while (bytesRead < len) {
        word = ptrace(PTRACE_PEEKTEXT, pid,
                      reinterpret_cast<uint8_t *>(addr) + bytesRead, NULL);
        if (word == -1) {
            std::cout << "[!] PTRACE_PEEKTEXT failed\n";
            return false;
        }
        bytesRead += sizeof(word);
        ptr[i++] = word;
    }
    return true;
}

bool ptrace_write(int64_t pid, void *addr, const void *ptr, size_t len) {
    int byteCount = 0;
    long word = 0;

    while (byteCount < len) {
        memcpy(&word, reinterpret_cast<const uint8_t *>(ptr) + byteCount,
               sizeof(word));
        word = ptrace(PTRACE_POKETEXT, pid,
                      reinterpret_cast<uint8_t *>(addr) + byteCount, word);
        if (word == -1) {
            std::cout << "[!] PTRACE_POKETEXT failed\n";
            return false;
        }
        byteCount += sizeof(word);
    }

    return true;
}

siginfo_t ptrace_getsiginfo(pid_t target) {
    siginfo_t targetsig;
    ptrace(PTRACE_GETSIGINFO, target, NULL, &targetsig);
    return targetsig;
}

void checktargetsig(int pid) {
    siginfo_t targetsig = ptrace_getsiginfo(pid);

    if (targetsig.si_signo != SIGTRAP) {
        fprintf(
            stderr,
            "instead of expected SIGTRAP, target stopped with signal %d: %s\n",
            targetsig.si_signo, strsignal(targetsig.si_signo));
        fprintf(stderr,
                "sending process %d a SIGSTOP signal for debugging purposes\n",
                pid);
        auto regs = get_regs(pid);
        std::cout << "rip = " << std::hex << regs.rip << std::dec << "\n";
        uint8_t buf[100]{};
        ptrace_read(pid, reinterpret_cast<void *>(regs.rip), buf, sizeof(buf));
        csh h{};
        cs_insn *insn{};
        size_t res{};

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) {
            std::cout << "[!] Capstone failed" << std::endl;
            return;
        }

        std::cout << "[+] cs_open done\n";

        cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
        size_t count = cs_disasm(h, reinterpret_cast<uint8_t *>(buf),
                                 sizeof(buf), regs.rip, 0, &insn);
        for (int i = 0; i < count; i++) {
            std::cout << std::hex << insn[i].address << "\t" << insn[i].mnemonic
                      << "\t" << insn[i].op_str << "\n";
        }
        ptrace(PTRACE_CONT, pid, NULL, SIGKILL);
        exit(1);
    }
}

bool ptrace_cont(int64_t pid) {
    auto sleeptime = new timespec;

    sleeptime->tv_sec = 0;
    sleeptime->tv_nsec = 5000000;

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        fprintf(stderr, "ptrace(PTRACE_CONT) failed\n");
        return false;
    }

    nanosleep(sleeptime, NULL);

    checktargetsig(pid);

    return true;
}

void *inject(int64_t pid, const std::string &lib) {
    std::cout << "[*] injecting " << lib << "\n";
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        std::cout << "[!] ptrace failed\n";
        return nullptr;
    }

    waitpid(pid, nullptr, 0);
    std::cout << "[+] ptrace attch\n";

    size_t shell_size = reinterpret_cast<uint8_t *>(&soloader_end) -
                        reinterpret_cast<uint8_t *>(&soloader);
    std::cout << "[*] shell_size = " << shell_size << "\n";
    std::cout << "Shell:\n" << std::hex;
    for (int i = 0; i < shell_size; i++) {
        std::cout << "0x"
                  << static_cast<uint64_t>(
                         reinterpret_cast<uint8_t *>(&soloader)[i])
                  << " ";
    }
    std::cout << std::dec << "\n";

    user_regs_struct regs = get_regs(pid);
    user_regs_struct orig_regs = regs;

    uint64_t malloc_ptr = get_func(pid, "malloc");
    uint64_t free_ptr = get_func(pid, "free");
    uint64_t dlopen_ptr = get_func(pid, "__libc_dlopen_mode");
    if (!dlopen_ptr) {
        dlopen_ptr = get_func(pid, "dlopen");
    }

    std::cout << std::hex;
    std::cout << "malloc_ptr: " << malloc_ptr << "\n";
    std::cout << "free_ptr: " << free_ptr << "\n";
    std::cout << "dlopen_ptr: " << dlopen_ptr << "\n";
    std::cout << std::dec;

    if (!malloc_ptr || !free_ptr || !dlopen_ptr) {
        return nullptr;
    }

    regs.rax = malloc_ptr;
    regs.rbx = free_ptr;
    regs.rdx = dlopen_ptr;

    void *shell_ptr = reinterpret_cast<void *>(find_xmem(pid));

    void *backup = std::malloc(shell_size);
    if (!ptrace_read(pid, shell_ptr, backup, shell_size)) {
        return nullptr;
    }
    if (!ptrace_write(pid, shell_ptr, reinterpret_cast<void *>(&soloader),
                      shell_size)) {
        std::cout << "[!] Can't write shell code\n";
        return nullptr;
    }

    std::cout << "[*] shell written to " << std::hex << shell_ptr << std::dec
              << "\n";

    regs.rip = reinterpret_cast<uint64_t>(shell_ptr);

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        std::cout << "[!] PTRACE_SETREGS failed\n";
        return nullptr;
    }

    if (!ptrace_cont(pid)) {
        return nullptr;
    }

    waitpid(pid, nullptr, 0);

    regs = get_regs(pid);

    std::cout << "[*] break after malloc (rip: 0x" << std::hex << regs.rip
              << std::dec << ")\n";
    regs = get_regs(pid);

    void *mem = reinterpret_cast<void *>(regs.rax);
    std::cout << "[+] malloc result: " << mem << "\n";
    char test[1000]{};
    memset(test, 0, sizeof(test));

    std::cout << "[*] want write " << lib << "\n";
    if (!ptrace_write(pid, mem, lib.c_str(), lib.size())) {
        std::cout << "[!] can't write lib path\n";
        return nullptr;
    }
    ptrace_read(pid, mem, test, lib.size());
    std::cout << "[*] written: " << test << "\n";

    std::cout << "[+] lib path written\n";

    if (!ptrace_cont(pid)) {
        return nullptr;
    }

    waitpid(pid, nullptr, 0);

    regs = get_regs(pid);
    std::cout << "[*] break after dlopen (rip: 0x" << std::hex << regs.rip
              << std::dec << ")\n";

    std::cout << "[*] dlopen returned " << std::hex << int64_t(regs.rax)
              << std::dec << "\n";

    if (!ptrace_write(pid, shell_ptr, backup, shell_size)) {
        std::cout << "[!] Can't write backup code back\n";
        return nullptr;
    }
    std::cout << "[+] backup restored\n";

    if (!set_regs(pid, orig_regs)) {
        std::cout << "[!] can't restore original registers\n";
        return nullptr;
    }
    std::cout << "[+] registers restored\n";

    if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
        std::cout << "PTRACE_DETACH failed\n";
        return nullptr;
    }

    std::cout << "[+] detached.\n";

    return nullptr;
}

void wait(void *t) {}
