#include "internal.hpp"

#include <Windows.h>
#include <cstring>

namespace protector {
namespace detail {

static const IMAGE_NT_HEADERS* nt_headers(const std::uint8_t* base)
{
    if (!base)
        return nullptr;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000)
        return nullptr;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;
    return nt;
}

bool text_section(void* image_base, Section* out)
{
    if (!image_base || !out)
        return false;

    const auto* base = static_cast<const std::uint8_t*>(image_base);
    const auto* nt = nt_headers(base);
    if (!nt)
        return false;

    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        char name[9]{};
        std::memcpy(name, section->Name, 8);
        if (std::strcmp(name, ".text") != 0)
            continue;

        out->data = const_cast<std::uint8_t*>(base + section->VirtualAddress);
        out->size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
        return out->size != 0;
    }
    return false;
}

std::uint32_t crc32(const std::uint8_t* data, std::size_t size)
{
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            const std::uint32_t mask = static_cast<std::uint32_t>(-(static_cast<std::int32_t>(crc) & 1));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

std::size_t count_int3(const Section& text)
{
    if (!text.data)
        return 0;
    std::size_t n = 0;
    for (std::size_t i = 0; i < text.size; ++i) {
        if (text.data[i] == 0xCC)
            ++n;
    }
    return n;
}

bool snapshot_text(void* image_base, std::uint32_t* out_crc, Section* out_text)
{
    Section text{};
    if (!text_section(image_base, &text))
        return false;
    *out_crc = crc32(text.data, text.size);
    if (out_text)
        *out_text = text;
    return true;
}

bool verify_text(const Section& text, std::uint32_t expected)
{
    if (!text.data || !text.size)
        return false;
    return crc32(text.data, text.size) == expected;
}

bool verify_text(void* image_base, std::uint32_t expected)
{
    Section text{};
    if (!text_section(image_base, &text))
        return false;
    return verify_text(text, expected);
}

} // namespace detail
} // namespace protector
