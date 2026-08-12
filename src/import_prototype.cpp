// centrifuge - import prototype recovery implementation.
#include "centrifuge/import_prototype.hpp"

#include <algorithm>
#include <cstring>
#include <functional>

namespace centrifuge {

namespace {

// Well-known CRT / Win32 prototypes, keyed by exported symbol name.
// Call-site evidence only *refines* these (widths, argument count); the
// knowledge table supplies the parameter count and shape so native output
// can name arguments even for imports called once or twice.
struct KnownPrototype {
    std::vector<DataType> parameters; // register parameters in ABI order
    std::vector<DataType> stackParameters;
    DataType returnType{TypeKind::VOID_TYPE, 0, 1};
    bool variadic = false;
};

const std::map<std::string, KnownPrototype>& knownPrototypes() {
    static const std::map<std::string, KnownPrototype> table = {
        {"malloc", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"calloc", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"realloc", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"free", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"memcpy", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"memmove", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"memset", {{{TypeKind::POINTER, 64, 1}, {TypeKind::SIGNED_INT, 32, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"memcmp", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"strlen", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 64, 1}, false}},
        {"strcpy", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"strncpy", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"strcmp", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"strncmp", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"strstr", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"strchr", {{{TypeKind::POINTER, 64, 1}, {TypeKind::SIGNED_INT, 32, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"strcat", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"strtol", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::SIGNED_INT, 32, 1}}, {}, {TypeKind::SIGNED_INT, 64, 1}, false}},
        {"strtod", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"getenv", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"exit", {{{TypeKind::SIGNED_INT, 32, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"abort", {{}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"printf", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, true}},
        {"fprintf", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, true}},
        {"sprintf", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, true}},
        {"snprintf", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, true}},
        {"sscanf", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, true}},
        {"swprintf", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, true}},
        {"qsort", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::FUNCTION_POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"bsearch", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::FUNCTION_POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"atoi", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"atof", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"rand", {{}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"srand", {{{TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"tolower", {{{TypeKind::SIGNED_INT, 32, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"toupper", {{{TypeKind::SIGNED_INT, 32, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"isalpha", {{{TypeKind::SIGNED_INT, 32, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"isdigit", {{{TypeKind::SIGNED_INT, 32, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"isspace", {{{TypeKind::SIGNED_INT, 32, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"isupper", {{{TypeKind::SIGNED_INT, 32, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"fopen", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"fclose", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"fread", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 64, 1}, false}},
        {"fwrite", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 64, 1}, false}},
        {"fgets", {{{TypeKind::POINTER, 64, 1}, {TypeKind::SIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"fputs", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"fgetc", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"fputc", {{{TypeKind::SIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"feof", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"ferror", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"fflush", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"remove", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"rename", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"sqrt", {{{TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"fabs", {{{TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"floor", {{{TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"ceil", {{{TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"pow", {{{TypeKind::FLOAT, 64, 1}, {TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"log", {{{TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"exp", {{{TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"sin", {{{TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"cos", {{{TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"tan", {{{TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"atan2", {{{TypeKind::FLOAT, 64, 1}, {TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"fmod", {{{TypeKind::FLOAT, 64, 1}, {TypeKind::FLOAT, 64, 1}}, {}, {TypeKind::FLOAT, 64, 1}, false}},
        {"lstrlenA", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"lstrlenW", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"lstrcpyA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"lstrcpyW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"lstrcmpA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"lstrcmpW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"GetProcAddress", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"GetModuleHandleA", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"GetModuleHandleW", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"GetModuleFileNameA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"GetModuleFileNameW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"LoadLibraryA", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"LoadLibraryW", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"FreeLibrary", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"GetLastError", {{}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"SetLastError", {{{TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"VirtualAlloc", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"VirtualFree", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"HeapAlloc", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"HeapFree", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"HeapReAlloc", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"GetProcessHeap", {{}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"GetCurrentProcess", {{}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"GetCurrentProcessId", {{}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"GetCurrentThreadId", {{}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"GetSystemTimeAsFileTime", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"GetTickCount", {{}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"GetTickCount64", {{}, {}, {TypeKind::UNSIGNED_INT, 64, 1}, false}},
        {"QueryPerformanceCounter", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"QueryPerformanceFrequency", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"Sleep", {{{TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"GetStdHandle", {{{TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"WriteFile", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"ReadFile", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"CloseHandle", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"CreateFileA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"CreateFileW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"FindFirstFileA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"FindFirstFileW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"FindNextFileA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"FindNextFileW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"FindClose", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"GetFileAttributesA", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"GetFileAttributesW", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"SetFileAttributesA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"SetFileAttributesW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"GetFileSize", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"GetFileSizeEx", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"SetFilePointer", {{{TypeKind::POINTER, 64, 1}, {TypeKind::SIGNED_INT, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"SetFilePointerEx", {{{TypeKind::POINTER, 64, 1}, {TypeKind::SIGNED_INT, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"DeleteFileA", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"DeleteFileW", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"MoveFileA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"MoveFileW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"CopyFileA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::BOOL, 32, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"CopyFileW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::BOOL, 32, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"GetCurrentDirectoryA", {{{TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"GetCurrentDirectoryW", {{{TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"SetCurrentDirectoryA", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"SetCurrentDirectoryW", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"CreateDirectoryA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"CreateDirectoryW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"RemoveDirectoryA", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"RemoveDirectoryW", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"GetTempPathA", {{{TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"GetTempPathW", {{{TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"GetEnvironmentVariableA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"GetEnvironmentVariableW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"SetEnvironmentVariableA", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"SetEnvironmentVariableW", {{{TypeKind::POINTER, 64, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"GetCommandLineA", {{}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"GetCommandLineW", {{}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"GetStartupInfoA", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"GetStartupInfoW", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"GetProcessHeap", {{}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"InitializeCriticalSection", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"EnterCriticalSection", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"LeaveCriticalSection", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"DeleteCriticalSection", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"GetCurrentThread", {{}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"GetCurrentThreadId", {{}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"TlsAlloc", {{}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"TlsFree", {{{TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"TlsGetValue", {{{TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"TlsSetValue", {{{TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"InterlockedIncrement", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"InterlockedDecrement", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::SIGNED_INT, 32, 1}, false}},
        {"InterlockedExchange", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 64, 1}, false}},
        {"InterlockedCompareExchange", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::UNSIGNED_INT, 64, 1}, false}},
        {"RtlInitializeCriticalSection", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"RtlEnterCriticalSection", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"RtlLeaveCriticalSection", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"RtlDeleteCriticalSection", {{{TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"RtlAllocateHeap", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"RtlFreeHeap", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"RtlReAllocateHeap", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}, {TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 64, 1}}, {}, {TypeKind::POINTER, 64, 1}, false}},
        {"RtlGetLastError", {{}, {}, {TypeKind::UNSIGNED_INT, 32, 1}, false}},
        {"RtlSetLastError", {{{TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::VOID_TYPE, 0, 1}, false}},
        {"RtlGenRandom", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
        {"SystemFunction036", {{{TypeKind::POINTER, 64, 1}, {TypeKind::UNSIGNED_INT, 32, 1}}, {}, {TypeKind::BOOL, 32, 1}, false}},
    };
    return table;
}

} // namespace

void ImportPrototypeRecovery::aggregate(const ProgramAnalysis& analysis,
                                        const Program& program) {
    std::map<uint64_t, size_t> byIat;
    for (size_t index = 0; index < program.imports.size(); ++index)
        byIat.emplace(program.imports[index].iatAddress, index);

    for (const auto& entry : analysis.functions())
        for (const AnalyzedCallSite& callSite : entry.second.callSites) {
            if (!callSite.target) continue;
            const auto found = byIat.find(*callSite.target);
            if (found == byIat.end()) continue;
            const ImportSymbol& symbol = program.imports[found->second];
            ImportPrototype& prototype = prototypes_[symbol.iatAddress];
            prototype.name = symbol.byOrdinal ? "" : symbol.name;
            prototype.library = symbol.library;
            prototype.iatAddress = symbol.iatAddress;
            prototype.byOrdinal = symbol.byOrdinal;
            ++prototype.callCount;
            const size_t registerArguments =
                std::min<size_t>(callSite.argInfo.size(), 4);
            prototype.maxRegisterArguments =
                std::max(prototype.maxRegisterArguments, registerArguments);
            if (prototype.mergedArgumentTypes.size() < registerArguments) {
                prototype.mergedArgumentTypes.resize(registerArguments);
                prototype.mergedArgumentWidths.resize(registerArguments, 0);
                prototype.argumentAddressUsed.resize(registerArguments, false);
            }
            for (size_t index = 0; index < registerArguments; ++index) {
                const CallSiteArgInfo& info = callSite.argInfo[index];
                if (!info.observed) continue;
                DataType& merged = prototype.mergedArgumentTypes[index];
                if (merged.kind == TypeKind::UNKNOWN && merged.bits == 0)
                    merged = info.type;
                else if (info.type.kind != TypeKind::UNKNOWN)
                    merged = mergeType(merged, info.type);
                prototype.mergedArgumentWidths[index] =
                    std::max(prototype.mergedArgumentWidths[index],
                             info.widthBytes);
                prototype.argumentAddressUsed[index] =
                    prototype.argumentAddressUsed[index] || info.addressUsed;
            }
            prototype.anyReturnValue |= callSite.returnsValue;
            prototype.returnDereferenced |= callSite.returnDereferenced;
            prototype.returnArithmetic |= callSite.returnArithmetic;
            prototype.returnBoolean |= callSite.returnBoolean;
            prototype.returnWidthBytes =
                std::max(prototype.returnWidthBytes,
                         callSite.returnWidthBytes);
        }
}

void ImportPrototypeRecovery::applyKnownPrototypes() {
    for (auto& entry : prototypes_) {
        ImportPrototype& prototype = entry.second;
        const std::string key = prototype.name;
        const auto known = knownPrototypes().find(key);
        if (known == knownPrototypes().end()) continue;
        const KnownPrototype& table = known->second;
        // Register parameters from the table, refined by evidence widths.
        // Win64 has four register arguments; any further table parameters
        // are stack arguments at [rsp+0x28+n*8].
        FunctionSignature& signature = prototype.signature;
        signature.parameters.clear();
        const auto abi = abiArguments("x86-64-win64", "win64");
        const size_t count = table.parameters.size();
        for (size_t index = 0; index < count; ++index) {
            FunctionParameter parameter;
            parameter.name = "arg" + std::to_string(index);
            DataType type = table.parameters[index];
            if (index < prototype.mergedArgumentWidths.size() &&
                prototype.mergedArgumentWidths[index] > 0 &&
                (type.kind == TypeKind::UNKNOWN ||
                 type.bits / 8 < prototype.mergedArgumentWidths[index])) {
                // Evidence says wider; keep the pointer-ness, widen the int.
                if (type.kind == TypeKind::UNSIGNED_INT ||
                    type.kind == TypeKind::SIGNED_INT)
                    type.bits = prototype.mergedArgumentWidths[index] * 8;
            }
            parameter.type = type;
            if (index < abi.size()) {
                parameter.registerOffset = abi[index].first;
            } else {
                parameter.onStack = true;
                parameter.stackOffset =
                    40 + static_cast<int64_t>(index - abi.size()) * 8;
            }
            signature.parameters.push_back(std::move(parameter));
        }
        for (size_t index = 0; index < table.stackParameters.size(); ++index) {
            FunctionParameter parameter;
            parameter.name = "stack_arg" + std::to_string(index);
            parameter.type = table.stackParameters[index];
            parameter.onStack = true;
            parameter.stackOffset = 40 + static_cast<int64_t>(index) * 8;
            signature.parameters.push_back(std::move(parameter));
        }
        signature.returnType = table.returnType;
        signature.variadic = table.variadic;
    }
}

std::optional<ImportPrototype> ImportPrototypeRecovery::prototypeFor(
    uint64_t iatAddress) const {
    const auto found = prototypes_.find(iatAddress);
    if (found == prototypes_.end()) return std::nullopt;
    return found->second;
}

} // namespace centrifuge
