#include "internal.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <intrin.h>

#include <cstring>

namespace protector {
namespace detail {
namespace {

using NtQueryInformationProcess_t = LONG(NTAPI*)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

NtQueryInformationProcess_t ntdll_query()
{
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return nullptr;
    return reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
}

bool peb_being_debugged()
{
#ifdef _WIN64
    const auto* peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
#else
    const auto* peb = reinterpret_cast<const std::uint8_t*>(__readfsdword(0x30));
#endif
    return peb && peb[2] != 0;
}

bool peb_nt_global_flag()
{
#ifdef _WIN64
    const auto* peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
    const auto flags = peb ? *reinterpret_cast<const std::uint32_t*>(peb + 0xBC) : 0;
#else
    const auto* peb = reinterpret_cast<const std::uint8_t*>(__readfsdword(0x30));
    const auto flags = peb ? *reinterpret_cast<const std::uint32_t*>(peb + 0x68) : 0;
#endif
    return (flags & 0x70u) != 0;
}

bool debug_port()
{
    auto* query = ntdll_query();
    if (!query)
        return false;

    PVOID port = nullptr;
    if (query(GetCurrentProcess(), 7, &port, sizeof(port), nullptr) != 0)
        return false;
    return port != nullptr;
}

bool debug_flags()
{
    auto* query = ntdll_query();
    if (!query)
        return false;

    ULONG flags = 1;
    if (query(GetCurrentProcess(), 0x1F, &flags, sizeof(flags), nullptr) != 0)
        return false;
    return flags == 0;
}

bool hardware_breakpoints()
{
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return false;
    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}

} // namespace

bool check_debugger()
{
    if (IsDebuggerPresent())
        return true;

    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote)
        return true;

    if (peb_being_debugged() || peb_nt_global_flag())
        return true;
    if (debug_port() || debug_flags())
        return true;
    if (hardware_breakpoints())
        return true;
    return false;
}

bool check_process_list(const std::vector<std::string>& names, std::string* hit)
{
    if (names.empty())
        return false;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            for (const auto& name : names) {
                wchar_t wide[MAX_PATH]{};
                MultiByteToWideChar(CP_ACP, 0, name.c_str(), -1, wide, MAX_PATH);
                if (_wcsicmp(pe.szExeFile, wide) == 0) {
                    if (hit)
                        *hit = name;
                    found = true;
                    break;
                }
            }
        } while (!found && Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return found;
}

bool check_window_list(const std::vector<std::string>& titles, std::string* hit)
{
    for (const auto& title : titles) {
        if (FindWindowA(nullptr, title.c_str())) {
            if (hit)
                *hit = title;
            return true;
        }
    }
    return false;
}

} // namespace detail
} // namespace protector
