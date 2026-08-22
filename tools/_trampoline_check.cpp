#include <cstdint>
#include <cstddef>
uint64_t FUN_000000014041F210(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4) {
    uint64_t rax = 0, rcx = 0, rdx = 0, r8 = 0, r9 = 0;
    rcx = (uint64_t)(uintptr_t)param1;
    rdx = (uint64_t)(uintptr_t)param2;
    r8 = (uint64_t)(uintptr_t)param3;
    r9 = (uint64_t)(uintptr_t)param4;
    // params: param1=rcx, param2=rdx, param3=r8, param4=r9
    rax = *(uint64_t *)(5475174752);
    return ((uint64_t (*)(...))(uintptr_t)rax)(rcx, rdx, r8, r9);
    return 0;
}

