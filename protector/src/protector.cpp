#include "internal.hpp"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace protector {
namespace {

struct State {
    Config cfg;
    void* image_base = nullptr;
    detail::Section text{};
    std::uint32_t text_crc = 0;
    std::size_t cc_baseline = 0;
    std::atomic<bool> run{false};
    bool process_wide = false;
    std::thread worker;
};

std::mutex g_mu;
std::vector<std::unique_ptr<State>> g_states;
std::atomic<bool> g_reported{false};

bool has_running_process_owner()
{
    for (const auto& s : g_states) {
        if (s && s->process_wide && s->run.load(std::memory_order_acquire))
            return true;
    }
    return false;
}

void report(const Config& cfg, Reason reason, const char* detail);

std::atomic<bool> g_timing_run{false};
std::atomic<std::uint64_t> g_heartbeat_qpc{0};
std::thread g_timing_thread;

void pulse_heartbeat()
{
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    g_heartbeat_qpc.store(static_cast<std::uint64_t>(now.QuadPart), std::memory_order_release);
}

double qpc_ms(const LARGE_INTEGER& freq, std::int64_t ticks)
{
    if (freq.QuadPart <= 0)
        return 0;
    return static_cast<double>(ticks) * 1000.0 / static_cast<double>(freq.QuadPart);
}

void fire_timing(const char* detail)
{
    Config cfg{};
    {
        std::lock_guard<std::mutex> lock(g_mu);
        for (const auto& s : g_states) {
            if (s && s->run.load(std::memory_order_acquire)) {
                cfg = s->cfg;
                break;
            }
        }
    }
    report(cfg, Reason::Debugger, detail);
}

void timing_loop()
{
    LARGE_INTEGER freq{};
    QueryPerformanceFrequency(&freq);
    Sleep(400);

    while (g_timing_run.load(std::memory_order_acquire)) {
        LARGE_INTEGER t0{}, t1{};
        QueryPerformanceCounter(&t0);
        Sleep(150);
        QueryPerformanceCounter(&t1);

        if (qpc_ms(freq, t1.QuadPart - t0.QuadPart) > 750.0) {
            fire_timing("timing_freeze");
            break;
        }

        const auto hb = g_heartbeat_qpc.load(std::memory_order_acquire);
        if (hb != 0) {
            LARGE_INTEGER now{};
            QueryPerformanceCounter(&now);
            if (qpc_ms(freq, now.QuadPart - static_cast<std::int64_t>(hb)) > 3000.0) {
                fire_timing("timing_heartbeat");
                break;
            }
        }
    }
}

void ensure_timing_thread()
{
    bool expected = false;
    if (!g_timing_run.compare_exchange_strong(expected, true))
        return;
    try {
        g_timing_thread = std::thread(timing_loop);
    } catch (...) {
        g_timing_run.store(false, std::memory_order_release);
    }
}

void stop_timing_thread()
{
    if (!g_timing_run.exchange(false, std::memory_order_acq_rel))
        return;
    if (g_timing_thread.joinable() && g_timing_thread.get_id() != std::this_thread::get_id())
        g_timing_thread.join();
}

void default_detect(Reason, const char*)
{
    TerminateProcess(GetCurrentProcess(), 0xDEADC0DEu);
}

void report(const Config& cfg, Reason reason, const char* detail)
{
    bool expected = false;
    if (!g_reported.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    if (cfg.on_detect)
        cfg.on_detect(reason, detail);
    else
        default_detect(reason, detail);
}

void* resolve_base(void* image_base)
{
    return image_base ? image_base : GetModuleHandleW(nullptr);
}

void watcher(State* s)
{
    while (s->run.load(std::memory_order_acquire)) {
        if (s->process_wide)
            pulse_heartbeat();

        if (s->process_wide && s->cfg.check_debugger && detail::check_debugger()) {
            report(s->cfg, Reason::Debugger, "debugger");
            break;
        }
        if (s->process_wide && s->cfg.check_debugger) {
            if (const char* why = detail::check_legacy(s->image_base, s->text, s->cc_baseline, false)) {
                report(s->cfg, Reason::Debugger, why);
                break;
            }
        }
        if (s->cfg.check_integrity && !detail::verify_text(s->text, s->text_crc)) {
            report(s->cfg, Reason::Integrity, ".text");
            break;
        }
        if (s->process_wide && s->cfg.check_process_blacklist) {
            std::string hit;
            if (detail::check_process_list(s->cfg.process_blacklist, &hit)) {
                report(s->cfg, Reason::Blacklist, hit.c_str());
                break;
            }
        }
        if (s->process_wide && s->cfg.check_window_blacklist) {
            std::string hit;
            if (detail::check_window_list(s->cfg.window_blacklist, &hit)) {
                report(s->cfg, Reason::Blacklist, hit.c_str());
                break;
            }
        }
        Sleep(s->cfg.poll_ms ? s->cfg.poll_ms : 250);
    }
}

void join_state(State* s)
{
    s->run.store(false, std::memory_order_release);
    if (s->worker.joinable() && s->worker.get_id() != std::this_thread::get_id())
        s->worker.join();
}

} // namespace

bool debugger_present()
{
    return detail::check_debugger();
}

bool integrity_ok(void* image_base)
{
    std::uint32_t crc = 0;
    return detail::snapshot_text(resolve_base(image_base), &crc);
}

bool start(const Config& cfg)
{
    auto state = std::make_unique<State>();
    state->cfg = cfg;
    state->image_base = resolve_base(cfg.image_base);

    if (state->cfg.process_blacklist.empty())
        state->cfg.process_blacklist = default_process_blacklist();
    if (state->cfg.window_blacklist.empty())
        state->cfg.window_blacklist = default_window_blacklist();

    note_own_image(state->image_base);

    auto step = [&](const char* name) {
        if (state->cfg.on_step)
            state->cfg.on_step(name);
    };

    bool own_process = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        own_process = !has_running_process_owner();
    }
    state->process_wide = own_process;

    if (state->cfg.check_integrity) {
        step("snapshot .text");
        if (!detail::snapshot_text(state->image_base, &state->text_crc, &state->text))
            return false;
        state->cc_baseline = detail::count_int3(state->text);
    }

    if (own_process && state->cfg.check_debugger) {
        step("debugger");
        if (detail::check_debugger()) {
            report(state->cfg, Reason::Debugger, "debugger");
            return false;
        }
        step("extra checks");
        if (const char* why = detail::check_legacy(state->image_base, state->text, state->cc_baseline, true)) {
            report(state->cfg, Reason::Debugger, why);
            return false;
        }
    }

    std::lock_guard<std::mutex> lock(g_mu);
    for (const auto& existing : g_states) {
        if (existing->image_base == state->image_base &&
            existing->run.load(std::memory_order_acquire)) {
            return true;
        }
    }

    state->run.store(true, std::memory_order_release);
    State* raw = state.get();
    try {
        raw->worker = std::thread(watcher, raw);
    } catch (...) {
        raw->run.store(false, std::memory_order_release);
        return false;
    }
    g_states.push_back(std::move(state));
    ensure_timing_thread();
    return true;
}

void stop(void* image_base)
{
    std::vector<std::unique_ptr<State>> dying;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        void* resolved = image_base ? resolve_base(image_base) : nullptr;
        auto it = g_states.begin();
        while (it != g_states.end()) {
            if (!resolved || (*it)->image_base == resolved) {
                dying.push_back(std::move(*it));
                it = g_states.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& s : dying)
        join_state(s.get());

    bool idle = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        idle = g_states.empty();
    }
    if (idle) {
        stop_timing_thread();
        g_reported.store(false, std::memory_order_release);
    }
}

bool running()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return std::any_of(g_states.begin(), g_states.end(), [](const auto& s) {
        return s->run.load(std::memory_order_acquire);
    });
}

const std::vector<std::string>& default_process_blacklist()
{
    static const std::vector<std::string> names = {
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "ida.exe",
        "ida64.exe",
        "idaq.exe",
        "idaq64.exe",
        "cheatengine-x86_64.exe",
        "cheatengine-i386.exe",
        "ceovr.exe",
        "Cheat Engine.exe",
        "KsDumperClient.exe",
        "KsDumper.exe",
        "HTTPDebuggerUI.exe",
        "HTTPDebuggerSvc.exe",
        "HTTP Debugger Windows Service (32 bit).exe",
        "FolderChangesView.exe",
        "procmon.exe",
        "Wireshark.exe",
        "Fiddler.exe",
        "Fiddler Everywhere.exe",
        "Xenos64.exe",
        "die.exe",
        "HxD64.exe",
        "HxD32.exe",
        "snowman.exe",
    };
    return names;
}

const std::vector<std::string>& default_window_blacklist()
{
    static const std::vector<std::string> titles = {
        "x64dbg",
        "x32dbg",
        "x64DBG",
        "x32DBG",
        "OllyDbg",
        "IDA",
        "IDA: Quick start",
        "Cheat Engine",
        "Cheat Engine 7.0",
        "Cheat Engine 7.1",
        "Cheat Engine 7.2",
        "Cheat Engine 7.3",
        "Cheat Engine 7.4",
        "Memory Viewer",
        "Process List",
        "KsDumper",
        "Fiddler Everywhere",
        "Fiddler Classic",
        "Fiddler Jam",
        "FiddlerCap",
        "FiddlerCore",
        "Scylla x86 v0.9.8",
        "Scylla x64 v0.9.8",
        "Scylla x86 v0.9.5a",
        "Scylla x64 v0.9.5a",
        "Scylla x86 v0.9.5",
        "Scylla x64 v0.9.5",
        "Detect It Easy v3.01",
        "HxD",
        "Snowman",
    };
    return titles;
}

} // namespace protector
