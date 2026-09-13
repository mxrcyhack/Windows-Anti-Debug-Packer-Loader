#include "detect_ui.hpp"
#include "dll_mapper.hpp"
#include "embedded_dll.h"
#include "protector.hpp"
#include <Windows.h>

#pragma comment(lib, "user32.lib")
#include <TlHelp32.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

struct Options {
    std::string dll_path;
    std::string process_name;
    DWORD pid = 0;
    bool self = true;
};

void print_usage()
{
    std::cout
        << "Windows Anti-Debug Packer & Loader\n\n"
        << "Usage:\n"
        << "  ProtectionLoader.exe [options]\n\n"
        << "Options:\n"
        << "  --dll <path>         Map a DLL from disk instead of the embedded image\n"
        << "  --self               Map into this process (default)\n"
        << "  --pid <id>           Map into a process you own, by PID\n"
        << "  --process <name>     Map into a process you own, by image name\n"
        << "  --help               Show this help\n\n"
        << "Only map into processes you own. System images (explorer, ctfmon, ...)\n"
        << "are rejected.\n";
}

bool parse_args(int argc, char** argv, Options* out)
{
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto need = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << name << "\n";
                return nullptr;
            }
            return argv[++i];
        };

        if (a == "--help" || a == "-h") {
            print_usage();
            return false;
        }
        if (a == "--self") {
            out->self = true;
            out->pid = 0;
            out->process_name.clear();
            continue;
        }
        if (a == "--dll") {
            const char* v = need("--dll");
            if (!v)
                return false;
            out->dll_path = v;
            continue;
        }
        if (a == "--pid") {
            const char* v = need("--pid");
            if (!v)
                return false;
            out->pid = static_cast<DWORD>(std::strtoul(v, nullptr, 10));
            out->self = false;
            continue;
        }
        if (a == "--process") {
            const char* v = need("--process");
            if (!v)
                return false;
            out->process_name = v;
            out->self = false;
            continue;
        }
        std::cerr << "Unknown option: " << a << "\n";
        print_usage();
        return false;
    }
    return true;
}

bool is_blocked_target(const char* image_name)
{
    static const char* k_blocked[] = {
        "csrss.exe",    "winlogon.exe", "wininit.exe",  "smss.exe",
        "lsass.exe",    "services.exe", "svchost.exe",  "explorer.exe",
        "ctfmon.exe",   "dwm.exe",      "sihost.exe",   "taskhostw.exe",
        "RuntimeBroker.exe", "SearchHost.exe", "System",
    };
    if (!image_name)
        return false;
    for (const char* name : k_blocked) {
        if (_stricmp(image_name, name) == 0)
            return true;
    }
    return false;
}

DWORD pid_by_name(const char* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    wchar_t wide[MAX_PATH]{};
    MultiByteToWideChar(CP_ACP, 0, name, -1, wide, MAX_PATH);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wide) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

bool process_image_name(DWORD pid, char* out, DWORD out_cch)
{
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc)
        return false;
    DWORD n = out_cch;
    const BOOL ok = QueryFullProcessImageNameA(proc, 0, out, &n);
    CloseHandle(proc);
    if (!ok)
        return false;
    char* slash = const_cast<char*>(strrchr(out, '\\'));
    if (slash)
        memmove(out, slash + 1, strlen(slash + 1) + 1);
    return true;
}

std::vector<std::uint8_t> read_file(const std::string& path)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
        return {};
    const auto size = file.tellg();
    if (size <= 0)
        return {};
    std::vector<std::uint8_t> bytes(static_cast<size_t>(size));
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(bytes.data()), size);
    return bytes;
}

bool call_init(HANDLE process, PBYTE image_base, DWORD rva, const protector::InitArgs& args, bool self)
{
    auto* fn = image_base + rva;
    if (self) {
        using Fn = DWORD(WINAPI*)(LPVOID);
        protector::InitArgs local = args;
        return reinterpret_cast<Fn>(fn)(&local) == 1;
    }

    void* remote = VirtualAllocEx(process, nullptr, sizeof(args), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
        return false;
    if (!WriteProcessMemory(process, remote, &args, sizeof(args), nullptr)) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = CreateRemoteThread(process, nullptr, 0,
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(fn), remote, 0, nullptr);
    if (!thread) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }

    const DWORD wait = WaitForSingleObject(thread, 15'000);
    DWORD code = 0;
    GetExitCodeThread(thread, &code);
    CloseHandle(thread);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return wait == WAIT_OBJECT_0 && code == 1;
}

} // namespace

int main(int argc, char** argv)
{
    Options opt{};
    if (!parse_args(argc, argv, &opt))
        return 2;

    protector::Config cfg{};
    cfg.check_debugger = true;
    cfg.check_integrity = true;
    cfg.check_process_blacklist = true;
    cfg.check_window_blacklist = true;
    cfg.on_step = [](const char* name) {
        std::cout << "  " << name << "...\n" << std::flush;
    };
    cfg.on_detect = [](protector::Reason reason, const char* detail) {
        std::cerr << "[protector] detect: " << (detail ? detail : "") << " ("
                  << static_cast<int>(reason) << ")\n"
                  << std::flush;
        show_protect_alert("loader", reason, detail);
        TerminateProcess(GetCurrentProcess(), 0xDEADC0DEu);
    };

    std::cout << "Starting loader protection...\n" << std::flush;
    if (!protector::start(cfg)) {
        std::cerr << "Failed to start loader protection.\n" << std::flush;
        return 1;
    }
    std::cout << "Loader protection is running.\n" << std::flush;

    HANDLE process = GetCurrentProcess();
    bool close_process = false;
    if (!opt.self) {
        DWORD pid = opt.pid;
        if (!pid && !opt.process_name.empty())
            pid = pid_by_name(opt.process_name.c_str());
        if (!pid) {
            std::cerr << "Target process not found.\n";
            return 1;
        }

        char image[MAX_PATH]{};
        if (process_image_name(pid, image, MAX_PATH) && is_blocked_target(image)) {
            std::cerr << "Refusing to map into system process: " << image << "\n";
            return 1;
        }
        if (!opt.process_name.empty() && is_blocked_target(opt.process_name.c_str())) {
            std::cerr << "Refusing to map into system process: " << opt.process_name << "\n";
            return 1;
        }

        process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                  PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                              FALSE, pid);
        if (!process) {
            std::cerr << "OpenProcess failed (" << GetLastError() << "). Use a process you own.\n";
            return 1;
        }
        close_process = true;
    }

    std::vector<std::uint8_t> bytes;
    if (!opt.dll_path.empty()) {
        bytes = read_file(opt.dll_path);
        if (bytes.size() < 0x1000) {
            std::cerr << "Cannot read DLL: " << opt.dll_path << "\n";
            if (close_process)
                CloseHandle(process);
            return 1;
        }
        std::cout << "Using DLL from disk: " << opt.dll_path << "\n";
    } else {
        bytes.assign(k_embedded_dll, k_embedded_dll + k_embedded_dll_size);
        if (bytes.size() < 0x1000) {
            std::cerr << "Embedded DLL is missing or corrupt. Rebuild the solution.\n";
            if (close_process)
                CloseHandle(process);
            return 1;
        }
        std::cout << "Using embedded DLL (" << bytes.size() << " bytes)\n";
    }

    const DWORD init_rva = find_export_rva(bytes.data(), "Protector_Init");
    if (!init_rva) {
        std::cerr << "DLL is missing export Protector_Init.\n";
        if (close_process)
            CloseHandle(process);
        return 1;
    }

    auto packet = protector::handshake::create();
    HANDLE lifetime = static_cast<HANDLE>(protector::handshake::create_lifetime_event(packet));
    if (!lifetime) {
        std::cerr << "Failed to create handshake event (" << GetLastError() << ").\n";
        if (close_process)
            CloseHandle(process);
        return 1;
    }

    PBYTE mapped = map_dll(process, bytes.data());
    if (mapped)
        protector::note_own_image(mapped);
    if (!mapped) {
        std::cerr << "Manual map failed.\n";
        CloseHandle(lifetime);
        if (close_process)
            CloseHandle(process);
        return 1;
    }

    protector::InitArgs args{};
    args.packet = packet;
    args.image_base = mapped;
    if (!call_init(process, mapped, init_rva, args, opt.self)) {
        std::cerr << "Protector_Init failed. The DLL stays inert.\n";
        unmap_dll(process, mapped);
        CloseHandle(lifetime);
        if (close_process)
            CloseHandle(process);
        return 1;
    }

    std::cout << "Mapped and armed at " << static_cast<void*>(mapped) << "\n";
    std::cout << "Loader + DLL protection running. Press Enter to unmap and exit.\n";
    std::cin.get();

    unmap_dll(process, mapped);
    CloseHandle(lifetime);
    if (close_process)
        CloseHandle(process);
    protector::stop();
    return 0;
}