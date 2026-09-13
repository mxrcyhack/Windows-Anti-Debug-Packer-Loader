#pragma once

#include <Windows.h>
#include <cstdint>

PBYTE map_dll(HANDLE process_handle, PBYTE buffer);
PBYTE map_dll(HANDLE process_handle, const char* dll_file_path);
bool unmap_dll(HANDLE process_handle, PBYTE image_base);
DWORD find_export_rva(PBYTE pe_image, const char* export_name);
