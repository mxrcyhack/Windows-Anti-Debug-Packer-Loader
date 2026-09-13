# mlprotect

Windows x64. Protects your loader and your mapped DLL.

The DLL stays dead until the loader maps it and calls `Protector_Init` with a handshake token. Both sides watch `.text`. Debugger / extra checks / blacklist run once per process (first `start()`), about every 250 ms. A second `start()` only watches that image’s `.text`. First hit exits the process.

Maps into this process by default. `--pid` / `--process` only for a process you own. System images (`ctfmon`, `explorer`, `lsass`, …) are refused. Needs administrator.

## Build

Visual Studio 2022, x64, `Protection.sln`. Output: `bin\x64\Release\ProtectionLoader.exe`.

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

## Run

```bat
ProtectionLoader.exe
ProtectionLoader.exe --dll path\to\yours.dll
ProtectionLoader.exe --dll yours.dll --pid 1234
ProtectionLoader.exe --dll yours.dll --process YourApp.exe
```

No args: protect the exe, map the DLL baked into the loader, wait for Enter.

To ship another DLL, open `ProtectionLoader.exe` in HxD and overwrite the embedded image with yours. Same size (or smaller). It must export `Protector_Init`. `--dll` loads one from disk instead, for testing.

## Use

Loader: `protector::start()`, handshake event, `map_dll`, call `Protector_Init`.

DLL: export `Protector_Init`, do nothing in `DllMain`. Validate the packet and that the loader event is still alive, then `protector::start()` with `image_base` = the mapped base.

```cpp
extern "C" __declspec(dllexport) DWORD WINAPI Protector_Init(LPVOID raw)
{
    auto* args = static_cast<const protector::InitArgs*>(raw);
    if (!args || !protector::handshake::valid(&args->packet))
        return 0;
    if (!protector::handshake::loader_alive(args->packet))
        return 0;
    protector::Config cfg{};
    cfg.image_base = args->image_base;
    return protector::start(cfg) ? 1 : 0;
}
```

## Checks

`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB `BeingDebugged` / `NtGlobalFlag`, `ProcessDebugPort`, `ProcessDebugFlags`, `ProcessDebugObjectHandle`, DR0–DR3, heap flags, `KUSER_SHARED_DATA`, `NtQueryObject`, `NtSystemDebugControl`, `ThreadHideFromDebugger`, hooks on debug APIs, `\\.\Dumper` / `\\.\KsDumper`.

Also on the timer: write-watch, page-guard, `PAGE_NOACCESS`, INT3, INT 2D, bad `CloseHandle` / `NtClose`, protected handle, `UnhandledExceptionFilter`, `timing_freeze`, `timing_heartbeat`.

Per image: CRC of `.text`, extra `0xCC`, private executable `MZ` (skips our own map).

Blacklist: x64dbg, IDA, Cheat Engine, and similar process / window names.

User-mode only. A kernel debugger can skip this.

## Layout

```
protector/   library (watcher, checks, handshake, mapper)
dll/         example DLL
loader/      example loader
Protection.sln
```

MIT. See [LICENSE](LICENSE).
