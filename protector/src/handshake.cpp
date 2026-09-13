#include "protector.hpp"

#include <Windows.h>
#include <bcrypt.h>

#include <cstring>

#pragma comment(lib, "bcrypt.lib")

namespace protector {
namespace handshake {
namespace {

std::wstring hex_token(const Packet& packet, std::size_t nbytes)
{
    static const wchar_t kHex[] = L"0123456789ABCDEF";
    std::wstring out(nbytes * 2, L'\0');
    for (std::size_t i = 0; i < nbytes; ++i) {
        out[i * 2] = kHex[(packet.token[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[packet.token[i] & 0xF];
    }
    return out;
}

} // namespace

Packet create()
{
    Packet packet{};
    packet.magic = k_magic;
    packet.version = k_version;
    BCryptGenRandom(nullptr, packet.token, sizeof(packet.token), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return packet;
}

bool valid(const Packet* packet)
{
    return packet && packet->magic == k_magic && packet->version == k_version;
}

std::wstring event_name(const Packet& packet)
{
    return L"Local\\mlprotect-" + hex_token(packet, 16);
}

void* create_lifetime_event(const Packet& packet)
{
    const std::wstring name = event_name(packet);
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    return CreateEventW(&sa, TRUE, FALSE, name.c_str());
}

bool loader_alive(const Packet& packet)
{
    const std::wstring name = event_name(packet);
    HANDLE ev = OpenEventW(SYNCHRONIZE, FALSE, name.c_str());
    if (!ev)
        return false;
    CloseHandle(ev);
    return true;
}

} // namespace handshake
} // namespace protector
