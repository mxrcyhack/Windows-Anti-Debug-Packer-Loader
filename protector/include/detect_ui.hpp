#pragma once

#include "protector.hpp"

#include <Windows.h>
#include <cstdio>

inline void show_protect_alert(const char* side, protector::Reason reason, const char* detail)
{
    const char* kind = "unknown";
    switch (reason) {
    case protector::Reason::Debugger:
        kind = "debugger / extra check";
        break;
    case protector::Reason::Integrity:
        kind = ".text integrity";
        break;
    case protector::Reason::Blacklist:
        kind = "process / window blacklist";
        break;
    case protector::Reason::Handshake:
        kind = "handshake";
        break;
    }

    char title[80]{};
    char body[512]{};
    sprintf_s(title, "Anti-Debug Packer - %s", side);
    sprintf_s(body, "%s\n%s", kind, (detail && detail[0]) ? detail : "");
    MessageBoxA(nullptr, body, title, MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND);
}
