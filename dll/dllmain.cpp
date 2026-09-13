#include "detect_ui.hpp"
#include "protector.hpp"

#include <Windows.h>

#pragma comment(lib, "user32.lib")

#include <atomic>

namespace {

std::atomic<bool> g_ready{false};
void* g_image = nullptr;

} // namespace

extern "C" __declspec(dllexport) DWORD WINAPI Protector_Init(LPVOID raw)
{
    const auto* args = static_cast<const protector::InitArgs*>(raw);
    if (!args || !protector::handshake::valid(&args->packet))
        return 0;
    if (!protector::handshake::loader_alive(args->packet))
        return 0;

    g_image = args->image_base;

    protector::Config cfg{};
    cfg.image_base = args->image_base;
    cfg.check_debugger = true;
    cfg.check_integrity = true;
    cfg.check_process_blacklist = true;
    cfg.check_window_blacklist = true;
    cfg.poll_ms = 250;
    cfg.on_detect = [](protector::Reason reason, const char* detail) {
        show_protect_alert("DLL", reason, detail);
        TerminateProcess(GetCurrentProcess(), 0xDEADC0DEu);
    };

    if (!protector::start(cfg))
        return 0;

    g_ready.store(true, std::memory_order_release);
    return 1;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
    } else if (reason == DLL_PROCESS_DETACH) {
        if (g_ready.load(std::memory_order_acquire))
            protector::stop(g_image);
    }
    return TRUE;
}
