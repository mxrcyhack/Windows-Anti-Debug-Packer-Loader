#include "internal.hpp"

#include <Windows.h>
#include <intrin.h>
#include <cstdio>

#include <mutex>
#include <vector>

namespace {
struct OwnSpan {
    const unsigned char* base = nullptr;
    std::size_t size = 0;
};

std::mutex g_own_mu;
std::vector<OwnSpan> g_own_images;

bool spans_overlap(const unsigned char* a, std::size_t asz, const unsigned char* b, std::size_t bsz)
{
    if (!a || !b || !asz || !bsz)
        return false;
    return a < b + bsz && b < a + asz;
}
}

namespace protector {

void note_own_image(void* image_base, std::size_t size)
{
    if (!image_base)
        return;

    if (size == 0) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(image_base, &mbi, sizeof(mbi))) {
            const auto* alloc = static_cast<const unsigned char*>(mbi.AllocationBase);
            const auto* self = static_cast<const unsigned char*>(image_base);
            size = mbi.RegionSize + static_cast<std::size_t>(self - alloc);
            if (mbi.RegionSize > size)
                size = mbi.RegionSize;
        }
        if (size == 0)
            size = 0x10000;
    }

    std::lock_guard<std::mutex> lock(g_own_mu);
    const auto* base = static_cast<const unsigned char*>(image_base);
    for (const auto& known : g_own_images) {
        if (known.base == base)
            return;
    }
    g_own_images.push_back({base, size});
}

namespace detail {

bool is_own_image(const void* address, std::size_t size)
{
    if (!address)
        return false;
    const auto* begin = static_cast<const unsigned char*>(address);
    if (size == 0)
        size = 1;

    std::lock_guard<std::mutex> lock(g_own_mu);
    for (const auto& known : g_own_images) {
        if (spans_overlap(begin, size, known.base, known.size))
            return true;
    }
    return false;
}

namespace {

using NtQuerySystemInformation_t = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationProcess_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSetInformationThread_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using NtQueryInformationThread_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtClose_t = LONG(NTAPI*)(HANDLE);
using NtQueryObject_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtCreateDebugObject_t = LONG(NTAPI*)(HANDLE*, ACCESS_MASK, void*, ULONG);
using NtSystemDebugControl_t = LONG(NTAPI*)(ULONG, void*, ULONG, void*, ULONG, PULONG);

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#endif
#ifndef STATUS_DATATYPE_MISALIGNMENT
#define STATUS_DATATYPE_MISALIGNMENT ((LONG)0x80000002L)
#endif
#ifndef STATUS_PORT_NOT_SET
#define STATUS_PORT_NOT_SET ((LONG)0xC0000353L)
#endif
#ifndef STATUS_DEBUGGER_INACTIVE
#define STATUS_DEBUGGER_INACTIVE ((LONG)0xC0000354L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((LONG)0xC0000022L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((LONG)0xC0000002L)
#endif
#ifndef STATUS_PRIVILEGE_NOT_HELD
#define STATUS_PRIVILEGE_NOT_HELD ((LONG)0xC0000061L)
#endif
#ifndef STATUS_INVALID_INFO_CLASS
#define STATUS_INVALID_INFO_CLASS ((LONG)0xC0000003L)
#endif

extern "C" void mlprotect_int2d();

volatile bool g_int2d_swallowed = true;
volatile bool g_uef_debugged = true;

LONG CALLBACK int2d_veh(PEXCEPTION_POINTERS info)
{
    g_int2d_swallowed = false;
    if (info && info->ExceptionRecord &&
        info->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI uef_filter(EXCEPTION_POINTERS*)
{
    g_uef_debugged = false;
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool address_in_module(HMODULE mod, const void* fn)
{
    if (!mod || !fn)
        return true;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(fn, &mbi, sizeof(mbi)))
        return true;
    return mbi.AllocationBase == static_cast<void*>(mod);
}

bool export_outside_home(HMODULE home, const void* fn)
{
    if (!fn)
        return false;
    if (address_in_module(home, fn))
        return false;
    if (address_in_module(GetModuleHandleW(L"kernelbase.dll"), fn))
        return false;
    if (address_in_module(GetModuleHandleW(L"ntdll.dll"), fn))
        return false;
    return true;
}

FARPROC ntdll_proc(const char* name)
{
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? GetProcAddress(ntdll, name) : nullptr;
}

bool hooked(const void* fn)
{
    if (!fn)
        return false;
    const auto* p = static_cast<const unsigned char*>(fn);
    if (p[0] == 0xE9 || p[0] == 0xCC)
        return true;
    if (p[0] == 0xFF && p[1] == 0x25)
        return true;
    return false;
}

} // namespace

#pragma optimize("", off)

__declspec(noinline) bool check_write_watch()
{
    PVOID mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE | MEM_WRITE_WATCH, PAGE_READWRITE);
    if (!mem)
        return false;

    PVOID hits[8]{};
    ULONG_PTR count = 8;
    ULONG gran = 0;
    const UINT err = GetWriteWatch(WRITE_WATCH_FLAG_RESET, mem, 0x1000, hits, &count, &gran);
    VirtualFree(mem, 0, MEM_RELEASE);
    return err == 0 && count > 0;
}

__declspec(noinline) bool check_page_guard()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    PVOID page = VirtualAlloc(nullptr, si.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page)
        return false;

    DWORD old = 0;
    if (!VirtualProtect(page, si.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &old)) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }

    volatile bool swallowed = true;
    __try {
        *static_cast<volatile char*>(page) = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        swallowed = false;
    }

    VirtualFree(page, 0, MEM_RELEASE);
    return swallowed;
}

__declspec(noinline) bool check_memory_breakpoint()
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    PVOID page = VirtualAlloc(nullptr, si.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page)
        return false;

    DWORD old = 0;
    if (!VirtualProtect(page, si.dwPageSize, PAGE_NOACCESS, &old)) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }

    volatile bool swallowed = true;
    __try {
        const char value = *static_cast<volatile char*>(page);
        (void)value;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        swallowed = false;
    }

    VirtualFree(page, 0, MEM_RELEASE);
    return swallowed;
}

__declspec(noinline) bool check_interrupt3()
{
    volatile bool caught = false;
    __try {
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        caught = true;
    }
    return !caught;
}

__declspec(noinline) bool check_invalid_handle()
{
    volatile bool raised = false;
    __try {
        CloseHandle(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xDEADBEEF)));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        raised = true;
    }
    return raised;
}

__declspec(noinline) bool check_nt_close()
{
    auto* nt_close = reinterpret_cast<NtClose_t>(ntdll_proc("NtClose"));
    if (!nt_close)
        return false;

    volatile bool raised = false;
    __try {
        nt_close(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xDEADBEEF)));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        raised = true;
    }
    return raised;
}

__declspec(noinline) bool check_protected_handle()
{
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ev)
        return false;

    SetHandleInformation(ev, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);

    volatile bool raised = false;
    __try {
        CloseHandle(ev);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        raised = true;
    }

    SetHandleInformation(ev, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
    CloseHandle(ev);
    return raised;
}

bool check_module_hooks()
{
    const HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    if (hooked(reinterpret_cast<void*>(IsDebuggerPresent)))
        return true;
    if (hooked(reinterpret_cast<void*>(CheckRemoteDebuggerPresent)))
        return true;
    if (hooked(ntdll_proc("NtQueryInformationProcess")))
        return true;
    if (hooked(ntdll_proc("NtSetInformationThread")))
        return true;
    if (hooked(ntdll_proc("NtQueryInformationThread")))
        return true;
    if (hooked(ntdll_proc("NtQueryObject")))
        return true;

    if (export_outside_home(k32, reinterpret_cast<void*>(IsDebuggerPresent)))
        return true;
    if (export_outside_home(k32, reinterpret_cast<void*>(CheckRemoteDebuggerPresent)))
        return true;
    if (export_outside_home(ntdll, ntdll_proc("NtQueryInformationProcess")))
        return true;
    if (export_outside_home(ntdll, ntdll_proc("NtSetInformationThread")))
        return true;
    return false;
}

bool check_kernel_debugger()
{
    auto* query = reinterpret_cast<NtQuerySystemInformation_t>(ntdll_proc("NtQuerySystemInformation"));
    if (!query)
        return false;

    struct {
        BOOLEAN debugger_enabled;
        BOOLEAN debugger_not_present;
    } info{};

    if (query(35, &info, sizeof(info), nullptr) != 0)
        return false;
    return info.debugger_enabled && !info.debugger_not_present;
}

bool check_dump_drivers()
{
    static const wchar_t* k_devices[] = {
        L"\\\\.\\Dumper",
        L"\\\\.\\KsDumper",
    };

    for (const wchar_t* name : k_devices) {
        HANDLE h = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return true;
        }
    }
    return false;
}

bool os_vista_or_greater()
{
    struct RtlOsVersion {
        ULONG dwOSVersionInfoSize;
        ULONG dwMajorVersion;
        ULONG dwMinorVersion;
        ULONG dwBuildNumber;
        ULONG dwPlatformId;
        WCHAR szCSDVersion[128];
    };
    using RtlGetVersion_t = LONG(NTAPI*)(RtlOsVersion*);
    auto* fn = reinterpret_cast<RtlGetVersion_t>(ntdll_proc("RtlGetVersion"));
    if (!fn)
        return false;
    RtlOsVersion info{};
    info.dwOSVersionInfoSize = sizeof(info);
    return fn(&info) == 0 && info.dwMajorVersion >= 6;
}


bool hide_thread_hooked(NtSetInformationThread_t set_info, NtQueryInformationThread_t query_info,
                        HANDLE thread)
{
    constexpr ULONG k_hide = 0x11;
    if (!set_info)
        return false;

    struct AlignedBool {
        alignas(4) bool value;
    };

    AlignedBool hidden{};
    hidden.value = false;

    LONG status = set_info(thread, k_hide, &hidden, 12345);
    if (status == 0)
        return true;

    status = set_info(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xFFFF)), k_hide, nullptr, 0);
    if (status == 0)
        return true;

    if (!query_info || !os_vista_or_greater())
        return false;

    status = query_info(thread, k_hide, &hidden.value, sizeof(bool), nullptr);
    if (status == STATUS_INFO_LENGTH_MISMATCH)
        return true;
    if (status != 0)
        return false;

    AlignedBool bogus{};
    bogus.value = false;
    status = query_info(thread, k_hide, &bogus.value, sizeof(BOOL), nullptr);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return true;

    constexpr size_t k_unaligned = 8;
#ifdef _WIN64
    constexpr size_t k_max_aligned = 2;
#else
    constexpr size_t k_max_aligned = 4;
#endif
    bool unaligned[k_unaligned]{};
    int alignment_errors = 0;
    for (size_t i = 0; i < k_unaligned; ++i) {
        status = query_info(thread, k_hide, &unaligned[i], sizeof(BOOL), nullptr);
        if (status == STATUS_DATATYPE_MISALIGNMENT)
            ++alignment_errors;
    }
    return k_unaligned - k_max_aligned > static_cast<size_t>(alignment_errors);
}

struct HideProbe {
    NtSetInformationThread_t set_info = nullptr;
    NtQueryInformationThread_t query_info = nullptr;
    bool hooked = false;
};

DWORD WINAPI hide_probe_worker(LPVOID param)
{
    auto* probe = static_cast<HideProbe*>(param);
    constexpr ULONG k_hide = 0x11;

    if (hide_thread_hooked(probe->set_info, probe->query_info, GetCurrentThread())) {
        probe->hooked = true;
        return 0;
    }

    const LONG status = probe->set_info(GetCurrentThread(), k_hide, nullptr, 0);
    if (status != 0) {
        probe->hooked = true;
        return 0;
    }

    if (!probe->query_info || !os_vista_or_greater())
        return 0;

    alignas(4) bool hidden = false;
    if (probe->query_info(GetCurrentThread(), k_hide, &hidden, sizeof(bool), nullptr) != 0)
        return 0;

    probe->hooked = !hidden;
    return 0;
}

bool check_hide_thread()
{
    auto* set_info = reinterpret_cast<NtSetInformationThread_t>(ntdll_proc("NtSetInformationThread"));
    auto* query_info = reinterpret_cast<NtQueryInformationThread_t>(ntdll_proc("NtQueryInformationThread"));
    if (!set_info)
        return false;

    if (hide_thread_hooked(set_info, query_info, GetCurrentThread()))
        return true;

    HideProbe probe{};
    probe.set_info = set_info;
    probe.query_info = query_info;
    HANDLE th = CreateThread(nullptr, 0, hide_probe_worker, &probe, 0, nullptr);
    if (!th)
        return false;
    const DWORD wait = WaitForSingleObject(th, 2000);
    CloseHandle(th);
    return wait == WAIT_OBJECT_0 && probe.hooked;
}

bool check_debug_object()
{
    auto* query = reinterpret_cast<NtQueryInformationProcess_t>(ntdll_proc("NtQueryInformationProcess"));
    if (!query)
        return false;

    constexpr ULONG k_class = 0x1E;
#ifdef _WIN64
    const ULONG length = sizeof(ULONG) * 2;
#else
    const ULONG length = sizeof(ULONG);
#endif

    HANDLE debug_object = nullptr;
    LONG status = query(GetCurrentProcess(), k_class, &debug_object, length, nullptr);
    if (status != STATUS_PORT_NOT_SET)
        return true;
    if (debug_object != nullptr)
        return true;

    debug_object = nullptr;
    status = query(GetCurrentProcess(), k_class, &debug_object, length,
                   reinterpret_cast<PULONG>(&debug_object));
    if (status != STATUS_PORT_NOT_SET)
        return true;
    if (debug_object == nullptr)
        return true;
    if (static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(debug_object)) != length)
        return true;
    return false;
}

__declspec(noinline) bool check_heap_flags()
{
#ifdef _WIN64
    volatile bool hit = false;
    __try {
        const auto* peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
        if (peb) {
            const auto heap = *reinterpret_cast<const std::uint64_t*>(peb + 0x30);
            if (heap) {
                const auto flags = *reinterpret_cast<const std::uint32_t*>(heap + 0x70);
                const auto force = *reinterpret_cast<const std::uint32_t*>(heap + 0x74);
                hit = flags > 2 || force > 0;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hit = false;
    }
    return hit;
#else
    return false;
#endif
}

bool check_shared_user_data()
{
    constexpr ULONG_PTR k_kuser = 0x7FFE0000;
    const auto byte = *reinterpret_cast<const std::uint8_t*>(k_kuser + 0x2D4);
    const bool enabled = (byte & 0x1u) != 0;
    const bool not_present = (byte & 0x2u) == 0;
    return enabled || !not_present;
}

bool check_query_object()
{
    auto* create = reinterpret_cast<NtCreateDebugObject_t>(ntdll_proc("NtCreateDebugObject"));
    auto* query = reinterpret_cast<NtQueryObject_t>(ntdll_proc("NtQueryObject"));
    if (!create || !query)
        return false;

    struct ObjectAttributes {
        ULONG Length;
        HANDLE RootDirectory;
        void* ObjectName;
        ULONG Attributes;
        void* SecurityDescriptor;
        void* SecurityQualityOfService;
    } oa{};
    oa.Length = sizeof(oa);

    constexpr ACCESS_MASK k_debug_all =
        STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0001 | 0x0002 | 0x0004 | 0x0008;

    HANDLE debug = nullptr;
    if (create(&debug, k_debug_all, &oa, 0) != 0 || !debug)
        return false;

    alignas(16) unsigned char memory[0x1000]{};
    struct ObjectTypeInformation {
        USHORT TypeNameLength;
        USHORT TypeNameMaximumLength;
        wchar_t* TypeNameBuffer;
        ULONG TotalNumberOfObjects;
        ULONG TotalNumberOfHandles;
    };
    auto* info = reinterpret_cast<ObjectTypeInformation*>(memory);
    const LONG status = query(debug, 2, memory, sizeof(memory), nullptr);
    CloseHandle(debug);

    if (status < 0)
        return false;
    return info->TotalNumberOfObjects == 0;
}

__declspec(noinline) bool check_interrupt_2d()
{
    PVOID veh = AddVectoredExceptionHandler(1, int2d_veh);
    if (!veh)
        return false;

    g_int2d_swallowed = true;
    __try {
        mlprotect_int2d();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_int2d_swallowed = false;
    }

    RemoveVectoredExceptionHandler(veh);
    return g_int2d_swallowed;
}

__declspec(noinline) bool check_unhandled_filter()
{
    g_uef_debugged = true;
    auto* previous = SetUnhandledExceptionFilter(uef_filter);
    RaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, nullptr);
    SetUnhandledExceptionFilter(previous);
    return g_uef_debugged;
}

bool check_system_debug_control()
{
    auto* fn = reinterpret_cast<NtSystemDebugControl_t>(ntdll_proc("NtSystemDebugControl"));
    if (!fn)
        return false;

    constexpr ULONG k_check_low_memory = 20;
    const LONG status = fn(k_check_low_memory, nullptr, 0, nullptr, 0, nullptr);
    if (status == STATUS_DEBUGGER_INACTIVE || status == STATUS_NOT_IMPLEMENTED ||
        status == STATUS_ACCESS_DENIED || status == STATUS_PRIVILEGE_NOT_HELD ||
        status == STATUS_INVALID_INFO_CLASS) {
        return false;
    }
    return true;
}

__declspec(noinline) bool readable_mz(const void* p)
{
    volatile bool hit = false;
    __try {
        const auto* mz = static_cast<const unsigned char*>(p);
        hit = mz[0] == 'M' && mz[1] == 'Z';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hit = false;
    }
    return hit;
}

#pragma optimize("", on)

bool check_manual_map()
{
    MEMORY_BASIC_INFORMATION mbi{};
    unsigned char* addr = nullptr;

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        const bool exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                          PAGE_EXECUTE_WRITECOPY)) != 0;
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && exec &&
            !is_own_image(mbi.BaseAddress, mbi.RegionSize) && mbi.RegionSize >= 2) {
            if (readable_mz(mbi.BaseAddress))
                return true;
        }

        auto* next = static_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr)
            break;
        addr = next;
    }
    return false;
}

bool check_software_breakpoints(const Section& text, std::size_t baseline)
{
    if (!text.data || !text.size)
        return false;
    return count_int3(text) > baseline;
}

const char* check_legacy(void* image_base, const Section& text, std::size_t cc_baseline, bool log)
{
    (void)image_base;
    static std::mutex legacy_mu;
    std::lock_guard<std::mutex> legacy_lock(legacy_mu);

    auto run = [log](const char* name, bool (*fn)()) -> const char* {
        if (log) {
            std::printf("    %s\n", name);
            std::fflush(stdout);
        }
        return fn() ? name : nullptr;
    };

    if (const char* h = run("write_watch", check_write_watch))
        return h;
    if (const char* h = run("page_breakpoint", check_page_guard))
        return h;
    if (const char* h = run("memory_breakpoint", check_memory_breakpoint))
        return h;
    if (const char* h = run("interrupt3", check_interrupt3))
        return h;
    if (const char* h = run("invalid_handle", check_invalid_handle))
        return h;
    if (const char* h = run("unhandle_debug", check_nt_close))
        return h;
    if (const char* h = run("protected_handle", check_protected_handle))
        return h;
    if (const char* h = run("module_hook", check_module_hooks))
        return h;
    if (const char* h = run("kernel_debugger", check_kernel_debugger))
        return h;
    if (const char* h = run("driver_detect", check_dump_drivers))
        return h;
    if (const char* h = run("ThreadHideFromDebugger", check_hide_thread))
        return h;
    if (const char* h = run("debug_object", check_debug_object))
        return h;
    if (const char* h = run("heap_flags", check_heap_flags))
        return h;
    if (const char* h = run("shared_user_data", check_shared_user_data))
        return h;
    if (const char* h = run("query_object", check_query_object))
        return h;
    if (const char* h = run("interrupt_2d", check_interrupt_2d))
        return h;
    if (const char* h = run("unhandled_filter", check_unhandled_filter))
        return h;
    if (const char* h = run("system_debug_control", check_system_debug_control))
        return h;
    if (log) {
        std::printf("    injection_detect\n");
        std::fflush(stdout);
    }
    if (check_manual_map())
        return "injection_detect";
    if (log) {
        std::printf("    software_breakpoints\n");
        std::fflush(stdout);
    }
    if (check_software_breakpoints(text, cc_baseline))
        return "software_breakpoints";
    return nullptr;
}

} // namespace detail
} // namespace protector
