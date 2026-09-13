#pragma once

#include "protector.hpp"

#include <cstddef>
#include <cstdint>

namespace protector {
namespace detail {

struct Section {
    std::uint8_t* data = nullptr;
    std::size_t size = 0;
};

bool text_section(void* image_base, Section* out);
std::uint32_t crc32(const std::uint8_t* data, std::size_t size);
std::size_t count_int3(const Section& text);
bool snapshot_text(void* image_base, std::uint32_t* out_crc, Section* out_text = nullptr);
bool verify_text(const Section& text, std::uint32_t expected);
bool verify_text(void* image_base, std::uint32_t expected);

bool is_own_image(const void* address, std::size_t size);

bool check_debugger();
const char* check_legacy(void* image_base, const Section& text, std::size_t cc_baseline, bool log);
bool check_process_list(const std::vector<std::string>& names, std::string* hit);
bool check_window_list(const std::vector<std::string>& titles, std::string* hit);

} // namespace detail
} // namespace protector
