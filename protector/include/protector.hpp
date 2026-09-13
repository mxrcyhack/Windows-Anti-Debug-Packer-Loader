#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace protector {

enum class Reason {
    Debugger,
    Integrity,
    Blacklist,
    Handshake,
};

struct Config {
    bool check_integrity = true;
    bool check_debugger = true;
    bool check_process_blacklist = true;
    bool check_window_blacklist = true;
    unsigned poll_ms = 250;
    std::function<void(const char* step)> on_step;
    void* image_base = nullptr;
    std::vector<std::string> process_blacklist;
    std::vector<std::string> window_blacklist;
    std::function<void(Reason, const char* detail)> on_detect;
};

bool start(const Config& cfg = {});
void stop(void* image_base = nullptr);
bool running();
bool debugger_present();
bool integrity_ok(void* image_base);
void note_own_image(void* image_base, std::size_t size = 0);

namespace handshake {

constexpr std::uint32_t k_magic = 0x50524F54;
constexpr std::uint32_t k_version = 1;

struct Packet {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint8_t token[32];
};

Packet create();
bool valid(const Packet* packet);
std::wstring event_name(const Packet& packet);
void* create_lifetime_event(const Packet& packet);
bool loader_alive(const Packet& packet);

}

struct InitArgs {
    handshake::Packet packet;
    void* image_base;
};

const std::vector<std::string>& default_process_blacklist();
const std::vector<std::string>& default_window_blacklist();

}
