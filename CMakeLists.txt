cmake_minimum_required(VERSION 3.20)
project(AntiDebugPackerLoader LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "Windows-only")
endif()

add_library(protector STATIC
    protector/src/protector.cpp
    protector/src/checks.cpp
    protector/src/handshake.cpp
    protector/src/integrity.cpp
    protector/src/dll_mapper.cpp
    protector/src/extra_checks.cpp
    protector/src/int2d.asm
)
target_include_directories(protector PUBLIC ${CMAKE_SOURCE_DIR}/protector/include)
target_compile_definitions(protector PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(protector PUBLIC bcrypt)

add_library(ProtectionDLL SHARED dll/dllmain.cpp dll/ProtectionDLL.def)
target_link_libraries(ProtectionDLL PRIVATE protector)
set_target_properties(ProtectionDLL PROPERTIES PREFIX "" OUTPUT_NAME ProtectionDLL)

set(EMBEDDED_DLL_HEADER ${CMAKE_CURRENT_BINARY_DIR}/generated/embedded_dll.h)
add_custom_command(
    OUTPUT ${EMBEDDED_DLL_HEADER}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/generated
    COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
            -File ${CMAKE_SOURCE_DIR}/tools/embed_dll.ps1
            -InputPath $<TARGET_FILE:ProtectionDLL>
            -OutputPath ${EMBEDDED_DLL_HEADER}
    DEPENDS ProtectionDLL ${CMAKE_SOURCE_DIR}/tools/embed_dll.ps1
    COMMENT "Embedding ProtectionDLL into the loader"
    VERBATIM
)

add_executable(ProtectionLoader loader/main.cpp ${EMBEDDED_DLL_HEADER})
target_include_directories(ProtectionLoader PRIVATE
    ${CMAKE_SOURCE_DIR}/loader
    ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(ProtectionLoader PRIVATE protector)
add_dependencies(ProtectionLoader ProtectionDLL)
target_link_options(ProtectionLoader PRIVATE
    "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
