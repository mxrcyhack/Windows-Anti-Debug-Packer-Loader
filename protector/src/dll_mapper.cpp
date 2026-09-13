#include "dll_mapper.hpp"
#include "protector.hpp"

#include <fstream>
#include <cstring>
#include <cstdlib>

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

using f_load_library_a = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_get_proc_address = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA {
    f_load_library_a p_load_library_a;
    f_get_proc_address p_get_proc_address;
    BYTE* p_address;
    HINSTANCE h_mod;
};

void __stdcall shellcode_attach(MANUAL_MAPPING_DATA* p_data);
void __stdcall shellcode_detach(MANUAL_MAPPING_DATA* p_data);

static const IMAGE_NT_HEADERS* pe_nt(PBYTE image)
{
    if (!image)
        return nullptr;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;
    return nt;
}

#ifdef _WIN64
static PRUNTIME_FUNCTION g_mapped_functions = nullptr;

static bool same_process(HANDLE process_handle)
{
    return GetProcessId(process_handle) == GetCurrentProcessId();
}

static void add_mapped_exceptions(PBYTE base)
{
    const auto* nt = pe_nt(base);
    if (!nt)
        return;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.VirtualAddress || !dir.Size)
        return;
    auto* functions = reinterpret_cast<PRUNTIME_FUNCTION>(base + dir.VirtualAddress);
    const DWORD count = dir.Size / sizeof(RUNTIME_FUNCTION);
    if (RtlAddFunctionTable(functions, count, reinterpret_cast<DWORD64>(base)))
        g_mapped_functions = functions;
}

static void remove_mapped_exceptions()
{
    if (!g_mapped_functions)
        return;
    RtlDeleteFunctionTable(g_mapped_functions);
    g_mapped_functions = nullptr;
}
#endif

static PBYTE rva_to_file(PBYTE image, DWORD rva)
{
    const auto* nt = pe_nt(image);
    if (!nt)
        return nullptr;

    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        const DWORD size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + size)
            return image + sec->PointerToRawData + (rva - sec->VirtualAddress);
    }
    if (rva < nt->OptionalHeader.SizeOfHeaders)
        return image + rva;
    return nullptr;
}

DWORD find_export_rva(PBYTE pe_image, const char* export_name)
{
    const auto* nt = pe_nt(pe_image);
    if (!nt || !export_name)
        return 0;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size)
        return 0;

    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(rva_to_file(pe_image, dir.VirtualAddress));
    if (!exp)
        return 0;

    auto* names = reinterpret_cast<DWORD*>(rva_to_file(pe_image, exp->AddressOfNames));
    auto* ords = reinterpret_cast<WORD*>(rva_to_file(pe_image, exp->AddressOfNameOrdinals));
    auto* funcs = reinterpret_cast<DWORD*>(rva_to_file(pe_image, exp->AddressOfFunctions));
    if (!names || !ords || !funcs)
        return 0;

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(rva_to_file(pe_image, names[i]));
        if (name && std::strcmp(name, export_name) == 0)
            return funcs[ords[i]];
    }
    return 0;
}

static bool execute_shellcode(HANDLE process_handle, void (*shellcode)(MANUAL_MAPPING_DATA*),
                              MANUAL_MAPPING_DATA data)
{
    PBYTE mmap_data = reinterpret_cast<PBYTE>(VirtualAllocEx(
        process_handle, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!mmap_data)
        return false;

    if (!WriteProcessMemory(process_handle, mmap_data, &data, sizeof(data), nullptr)) {
        VirtualFreeEx(process_handle, mmap_data, 0, MEM_RELEASE);
        return false;
    }

    void* p_shellcode = VirtualAllocEx(process_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!p_shellcode) {
        VirtualFreeEx(process_handle, mmap_data, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(process_handle, p_shellcode, shellcode, 0x1000, nullptr)) {
        VirtualFreeEx(process_handle, mmap_data, 0, MEM_RELEASE);
        VirtualFreeEx(process_handle, p_shellcode, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = CreateRemoteThread(process_handle, nullptr, 0,
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(p_shellcode),
                                       mmap_data, 0, nullptr);
    if (!thread) {
        VirtualFreeEx(process_handle, mmap_data, 0, MEM_RELEASE);
        VirtualFreeEx(process_handle, p_shellcode, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(thread, 15'000);
    CloseHandle(thread);

    HINSTANCE check = nullptr;
    const ULONGLONG start = GetTickCount64();
    while (!check) {
        DWORD exitcode = 0;
        if (!GetExitCodeProcess(process_handle, &exitcode) || exitcode != STILL_ACTIVE)
            break;

        MANUAL_MAPPING_DATA remote{};
        if (!ReadProcessMemory(process_handle, mmap_data, &remote, sizeof(remote), nullptr))
            break;
        check = remote.h_mod;

        if (check == reinterpret_cast<HINSTANCE>(0x404040) ||
            check == reinterpret_cast<HINSTANCE>(0x606060)) {
            VirtualFreeEx(process_handle, mmap_data, 0, MEM_RELEASE);
            VirtualFreeEx(process_handle, p_shellcode, 0, MEM_RELEASE);
            return false;
        }
        if (GetTickCount64() - start > 15'000)
            break;
        Sleep(10);
    }

    VirtualFreeEx(process_handle, p_shellcode, 0, MEM_RELEASE);
    VirtualFreeEx(process_handle, mmap_data, 0, MEM_RELEASE);
    return check != nullptr;
}

static PBYTE map_dll_buffer(HANDLE process_handle, PBYTE buffer, bool from_file)
{
    const auto* nt = pe_nt(buffer);
    if (!nt) {
        if (from_file)
            std::free(buffer);
        return nullptr;
    }

    if (nt->FileHeader.Machine != CURRENT_ARCH) {
        if (from_file)
            std::free(buffer);
        return nullptr;
    }

    const auto* opt = &nt->OptionalHeader;
    PBYTE remote = reinterpret_cast<PBYTE>(VirtualAllocEx(
        process_handle, nullptr, opt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!remote) {
        if (from_file)
            std::free(buffer);
        return nullptr;
    }

    protector::note_own_image(remote, opt->SizeOfImage);

    MANUAL_MAPPING_DATA data{};
    data.p_load_library_a = LoadLibraryA;
    data.p_get_proc_address = GetProcAddress;
    data.p_address = remote;

    if (!WriteProcessMemory(process_handle, remote, buffer, 0x1000, nullptr)) {
        VirtualFreeEx(process_handle, remote, 0, MEM_RELEASE);
        if (from_file)
            std::free(buffer);
        return nullptr;
    }

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (UINT i = 0; i != nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (!section->SizeOfRawData)
            continue;
        if (!WriteProcessMemory(process_handle, remote + section->VirtualAddress,
                                buffer + section->PointerToRawData, section->SizeOfRawData, nullptr)) {
            VirtualFreeEx(process_handle, remote, 0, MEM_RELEASE);
            if (from_file)
                std::free(buffer);
            return nullptr;
        }
    }

    if (!execute_shellcode(process_handle, shellcode_attach, data)) {
        VirtualFreeEx(process_handle, remote, 0, MEM_RELEASE);
        if (from_file)
            std::free(buffer);
        return nullptr;
    }

#ifdef _WIN64
    if (same_process(process_handle))
        add_mapped_exceptions(remote);
#endif

    if (from_file)
        std::free(buffer);
    return remote;
}

PBYTE map_dll(HANDLE process_handle, PBYTE buffer)
{
    return map_dll_buffer(process_handle, buffer, false);
}

PBYTE map_dll(HANDLE process_handle, const char* dll_file_path)
{
    if (!dll_file_path || GetFileAttributesA(dll_file_path) == INVALID_FILE_ATTRIBUTES)
        return nullptr;

    std::ifstream file(dll_file_path, std::ios::binary | std::ios::ate);
    if (!file)
        return nullptr;

    const auto size = file.tellg();
    if (size < 0x1000)
        return nullptr;

    auto* buffer = static_cast<PBYTE>(std::malloc(static_cast<size_t>(size)));
    if (!buffer)
        return nullptr;

    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer), size);
    file.close();
    return map_dll_buffer(process_handle, buffer, true);
}

bool unmap_dll(HANDLE process_handle, PBYTE image_base)
{
#ifdef _WIN64
    if (same_process(process_handle))
        remove_mapped_exceptions();
#endif
    MANUAL_MAPPING_DATA data{};
    data.p_address = image_base;
    if (!execute_shellcode(process_handle, shellcode_detach, data))
        return false;
    VirtualFreeEx(process_handle, image_base, 0, MEM_RELEASE);
    return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks("", off)
#pragma optimize("", off)

void __stdcall shellcode_attach(MANUAL_MAPPING_DATA* p_data)
{
    if (!p_data) {
        return;
    }


    PBYTE p_address = p_data->p_address;
    auto* p_opt = &reinterpret_cast<PIMAGE_NT_HEADERS>(
                      p_address + reinterpret_cast<PIMAGE_DOS_HEADER>(p_address)->e_lfanew)
                       ->OptionalHeader;

    auto _load_library_a = p_data->p_load_library_a;
    auto _get_proc_address = p_data->p_get_proc_address;
    auto _dll_main = reinterpret_cast<f_DLL_ENTRY_POINT>(p_address + p_opt->AddressOfEntryPoint);

    const UINT_PTR location_delta =
        reinterpret_cast<UINT_PTR>(p_address) - static_cast<UINT_PTR>(p_opt->ImageBase);
    if (location_delta) {
        if (!p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            p_data->h_mod = reinterpret_cast<HINSTANCE>(0x606060);
            return;
        }

        auto* p_reloc_data = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            p_address + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (p_reloc_data->VirtualAddress) {
            UINT amount_of_entries =
                (p_reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto* p_relative_info = reinterpret_cast<PWORD>(p_reloc_data + 1);

            for (UINT i = 0; i != amount_of_entries; ++i, ++p_relative_info) {
                if (RELOC_FLAG(*p_relative_info)) {
                    auto* p_patch = reinterpret_cast<UINT_PTR*>(
                        p_address + p_reloc_data->VirtualAddress + ((*p_relative_info) & 0xFFF));
                    *p_patch += location_delta;
                }
            }
            p_reloc_data = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<BYTE*>(p_reloc_data) + p_reloc_data->SizeOfBlock);
        }
    }

    if (p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* p_import_descr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            p_address + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (p_import_descr->Name) {
            char* sz_mod = reinterpret_cast<char*>(p_address + p_import_descr->Name);
            HINSTANCE h_dll = _load_library_a(sz_mod);

            auto* p_thunk_ref = reinterpret_cast<ULONG_PTR*>(p_address + p_import_descr->OriginalFirstThunk);
            auto* p_func_ref = reinterpret_cast<ULONG_PTR*>(p_address + p_import_descr->FirstThunk);
            if (!p_thunk_ref)
                p_thunk_ref = p_func_ref;

            for (; *p_thunk_ref; ++p_thunk_ref, ++p_func_ref) {
                if (IMAGE_SNAP_BY_ORDINAL(*p_thunk_ref)) {
                    *p_func_ref = reinterpret_cast<ULONG_PTR>(
                        _get_proc_address(h_dll, reinterpret_cast<char*>(*p_thunk_ref & 0xFFFF)));
                } else {
                    auto* p_import = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(p_address + (*p_thunk_ref));
                    *p_func_ref = reinterpret_cast<ULONG_PTR>(_get_proc_address(h_dll, p_import->Name));
                }
            }
            ++p_import_descr;
        }
    }

    if (p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* p_tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
            p_address + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* p_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(p_tls->AddressOfCallBacks);
        for (; p_callback && *p_callback; ++p_callback)
            (*p_callback)(p_address, DLL_PROCESS_ATTACH, nullptr);
    }

    _dll_main(p_address, DLL_PROCESS_ATTACH, nullptr);
    p_data->h_mod = reinterpret_cast<HINSTANCE>(p_address);
}

void __stdcall shellcode_detach(MANUAL_MAPPING_DATA* p_data)
{
    if (!p_data)
        return;

    PBYTE p_address = p_data->p_address;
    auto* p_opt = &reinterpret_cast<PIMAGE_NT_HEADERS>(
                      p_address + reinterpret_cast<PIMAGE_DOS_HEADER>(p_address)->e_lfanew)
                       ->OptionalHeader;
    auto _dll_main = reinterpret_cast<f_DLL_ENTRY_POINT>(p_address + p_opt->AddressOfEntryPoint);

    if (p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* p_tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
            p_address + p_opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* p_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(p_tls->AddressOfCallBacks);
        for (; p_callback && *p_callback; ++p_callback)
            (*p_callback)(p_address, DLL_PROCESS_DETACH, nullptr);
    }

    _dll_main(p_address, DLL_PROCESS_DETACH, nullptr);
    p_data->h_mod = reinterpret_cast<HINSTANCE>(p_address);
}

#pragma optimize("", on)
#pragma runtime_checks("", restore)
