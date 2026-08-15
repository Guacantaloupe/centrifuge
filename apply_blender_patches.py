#!/usr/bin/env python3
"""Re-apply runtime-generation patches to a freshly recovered Blender 5.2 project.

Run from build-blender52/project after re-running recovery (which overwrites
src/recovered_*.cpp, external_stubs.cpp, include/recovered.hpp).

Patch set (data-slot thunks are handled separately by thunk_fix.py; the
allocator targets themselves are now recovered via the data-pointer root scan
in ProgramAnalysis::build, so external stub special-casing is NOT applied):

1. GS-cookie call must not clobber RAX: recovered `rax = FUN_4685720(...)`
   (__security_check_cookie restored as value-returning) overwrites the real
   result (memchr end pointer etc.) with the cookie check's RAX.  Native
   __security_check_cookie is a transparent void call.
2. _Mtx_lock/_Mtx_unlock no-op in the single-threaded recovered runtime
   (MSVCP140 locks abort in a non-MSVC-CRT process).
3. FUN_04E2830 (UTF-8 decode precondition check) was inferred as uint32_t but
   returns a pointer (arg1 or the transcoded result of FUN_04E2120); the
   uint32_t return truncates the pointer and FUN_0389480 crashes reading
   0x46624658 == (uint32_t)r15.  Native returns RAX full width.
"""
import glob, io, os, re, sys

def load(p):
    with open(p, 'rb') as f:
        return f.read().decode('utf-8-sig')

def save(p, s):
    with open(p, 'w', encoding='utf-8', newline='') as f:
        f.write(s)

def main():
    src_dir = sys.argv[1] if len(sys.argv) > 1 else 'src'
    # 1. GS-cookie rax clobber across all recovered sources
    total = 0
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        n = src.count('rax = FUN_0000000144685720(')
        if n:
            src = src.replace('rax = FUN_0000000144685720(',
                              'FUN_0000000144685720(')
            save(path, src)
            total += n
    print(f'GS-cookie rax clobber fixed: {total} sites')

    # 2. _Mtx_lock / _Mtx_unlock no-op (single-threaded recovered runtime)
    for target in ['4C0C730', '4C0C740']:
        pat = re.compile(
            r'uint64_t FUN_000000014' + target + r'\([^)]*\) \{(?:(?!\n\}\n).)*?\n\}\n',
            re.S)
        found = False
        for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
            src = load(path)
            m = pat.search(src)
            if m:
                body = src[m.start():m.end()]
                if 'import_' in body:
                    noop = ('uint64_t FUN_000000014' + target +
                            '(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3) {\n'
                            '    (void)arg0; (void)arg1; (void)arg2; (void)arg3;\n'
                            '    return 0; /* lock no-op in single-threaded recovered runtime */\n}\n')
                    save(path, src[:m.start()] + noop + src[m.end():])
                    print(f'no-op FUN_{target} in {path}')
                    found = True
                    break
        if not found:
            print(f'!! FUN_{target} not found with import body')

    # 3. FUN_04E2830 must return uint64_t (pointer-returning; uint32_t truncated
    #    the source pointer passed to FUN_0389480, crashing on 0x46624658)
    ret_fixed = 0
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        if 'uint32_t FUN_00000001404E2830(' in src:
            src = src.replace('uint32_t FUN_00000001404E2830(',
                              'uint64_t FUN_00000001404E2830(')
            save(path, src)
            ret_fixed += 1
    hpp = sorted(glob.glob(src_dir + '/../include/recovered.hpp'))
    if hpp:
        src = load(hpp[0])
        if 'uint32_t FUN_00000001404E2830(' in src:
            src = src.replace('uint32_t FUN_00000001404E2830(',
                              'uint64_t FUN_00000001404E2830(')
            save(hpp[0], src)
            ret_fixed += 1
    print(f'FUN_04E2830 return type fixed: {ret_fixed} sites')

    # 4. external_140dd1820 ... already applied above ...
    stub_path = src_dir + '/external_stubs.cpp'
    if os.path.exists(stub_path):
        src = load(stub_path)
        old = ('std::uint64_t external_140dd1820(std::uint64_t a0, std::uint64_t a1, '
               'std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, '
               'std::uint64_t a6, std::uint64_t a7) {\n'
               '    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; '
               '(void)a6; (void)a7;\n'
               '    return 0;\n}')  # exactly the generated plain stub
        if old in src:
            new = ('std::uint64_t external_140dd1820(std::uint64_t a0, std::uint64_t a1, '
                   'std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, '
                   'std::uint64_t a6, std::uint64_t a7) {\n'
                   '    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; '
                   '(void)a6; (void)a7;\n'
                   '    // Native: delayed-init singleton accessor returning a global\n'
                   '    // BSS object (RVA 0x7022F08); the plain stub returned 0 and\n'
                   '    // FUN_0458430 used 0+64 as a container pointer.  Return a\n'
                   '    // persistent zero-initialized host buffer (mirror BSS tail may\n'
                   '    // be uncommitted; object state must survive across calls).\n'
                   '    static std::uint64_t singleton_obj[512] = {};\n'
                   '    return reinterpret_cast<std::uint64_t>(singleton_obj);\n}')
            save(stub_path, src.replace(old, new))
            print('external_140dd1820 host-object patch applied')
        else:
            print('external_140dd1820 stub not plain (already patched or recovered)')

    # 5. Free slot (data slot 0x146588940 -> aligned_free chain): upstream
    #    state drift hands it pointers that were never host-allocated, so a
    #    real free crashes RtlFreeHeap.  Leak instead of crashing.
    if os.path.exists(stub_path):
        src = load(stub_path)
        old = ('external_146588940(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, '
               'std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, '
               'std::uint64_t a7) {\n'
               '    const auto target = recovered_load<std::uint64_t>(0x146588940);\n'
               '    if (target >= 5368709120ULL && target < 5494044672ULL)\n'
               '        return recovered_dispatch(target, a0, a1, a2, a3, a4, a5, a6, a7);\n'
               '    auto function = reinterpret_cast<RecoveredExternal>(target);\n'
               '    return function ? function(recovered_external_argument(a0), '
               'recovered_external_argument(a1), recovered_external_argument(a2), '
               'recovered_external_argument(a3), recovered_external_argument(a4), '
               'recovered_external_argument(a5), recovered_external_argument(a6), '
               'recovered_external_argument(a7)) : 0;\n}')
        if old in src:
            new = ('external_146588940(std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, '
                   'std::uint64_t a3, std::uint64_t a4, std::uint64_t a5, std::uint64_t a6, '
                   'std::uint64_t a7) {\n'
                   '    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; '
                   '(void)a6; (void)a7;\n'
                   '    // Free slot: leak instead of crashing on never-host-allocated '
                   'pointers.\n'
                   '    return 0;\n}')
            save(stub_path, src.replace(old, new))
            print('external_146588940 free no-op applied')
        else:
            print('external_146588940 stub not plain (already patched or recovered)')

    # 6. FUN_0B0D4E0 alloca-style stack allocator: recovery returns the
    #    aligned size (e.g. 0x800) instead of a writable pointer; hand back
    #    host memory so GetModuleFileNameW's buffer is real.
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        pat = re.compile(
            r'uint64_t FUN_0000000140B0D4E0\([^)]*\) \{(?:(?!\n\}\n).)*?\n\}\n', re.S)
        m = pat.search(src)
        if m and 'alloca-style' not in src[m.start():m.end()]:
            new = ('uint64_t FUN_0000000140B0D4E0(uint64_t arg0, uint64_t arg1, '
                   'uint64_t arg2, uint64_t arg3) {\n'
                   '    (void)arg1; (void)arg2; (void)arg3;\n'
                   '    // Native: alloca-style stack allocator (alignment computation '
                   '+ stack\n'
                   '    // bump returning a stack pointer).  Recovery lost the '
                   'stack-pointer return\n'
                   '    // (returned the aligned size, e.g. 0x800, not writable).  '
                   'Return host memory.\n'
                   '    return reinterpret_cast<std::uint64_t>(::operator '
                   'new(arg0 ? arg0 : 1));\n}\n')
            save(path, src[:m.start()] + new + src[m.end():])
            print(f'FUN_0B0D4E0 alloca host-ized in {path}')
            break
    else:
        print('FUN_0B0D4E0 not found')

    # 7. recovered_main.cpp: vectored crash handler writing crash_report.txt
    #    (fast crash diagnostics without gdb, which is unusably slow here).
    main_path = src_dir + '/recovered_main.cpp'
    if os.path.exists(main_path):
        src = load(main_path)
        if 'recovered_crash_handler' not in src:
            guard = ('#ifdef _WIN32\n#include <windows.h>\n#endif\n'
                     'int main(int argc, char** argv) {')
            if guard in src:
                new = ('#ifdef _WIN32\n#include <windows.h>\n#include <dbghelp.h>\n'
                       'static LONG WINAPI recovered_crash_handler(EXCEPTION_POINTERS* ep) {\n'
                       '    if (ep->ExceptionRecord->ExceptionCode != '
                       'EXCEPTION_ACCESS_VIOLATION &&\n'
                       '        ep->ExceptionRecord->ExceptionCode != '
                       'EXCEPTION_STACK_OVERFLOW &&\n'
                       '        ep->ExceptionRecord->ExceptionCode != 0xC0000409)\n'
                       '        return EXCEPTION_CONTINUE_SEARCH;\n'
                       '    HANDLE hf = CreateFileA("crash_report.txt", GENERIC_WRITE, '
                       'FILE_SHARE_READ,\n'
                       '        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);\n'
                       '    if (hf != INVALID_HANDLE_VALUE) {\n'
                       '        DWORD wrote = 0;\n'
                       '        SetFilePointer(hf, 0, nullptr, FILE_END);\n'
                       '        char buf[512];\n'
                       '        int bl = std::snprintf(buf, sizeof(buf),\n'
                       '            "CRASH code=%08lx rip=%p rax=%p rcx=%p rdx=%p rbx=%p '
                       'rsi=%p rdi=%p r8=%p r9=%p r12=%p r13=%p r14=%p r15=%p\\n",\n'
                       '            (unsigned long)ep->ExceptionRecord->ExceptionCode,\n'
                       '            (void*)ep->ContextRecord->Rip, (void*)ep->ContextRecord->Rax,\n'
                       '            (void*)ep->ContextRecord->Rcx, (void*)ep->ContextRecord->Rdx,\n'
                       '            (void*)ep->ContextRecord->Rbx, (void*)ep->ContextRecord->Rsi,\n'
                       '            (void*)ep->ContextRecord->Rdi, (void*)ep->ContextRecord->R8,\n'
                       '            (void*)ep->ContextRecord->R9, (void*)ep->ContextRecord->R12,\n'
                       '            (void*)ep->ContextRecord->R13, (void*)ep->ContextRecord->R14,\n'
                       '            (void*)ep->ContextRecord->R15);\n'
                       '        if (bl > 0) WriteFile(hf, buf, (DWORD)bl, &wrote, nullptr);\n'
                       '        const std::uintptr_t crsp = '
                       'reinterpret_cast<std::uintptr_t>(ep->ContextRecord->Rsp);\n'
                       '        HMODULE exe = GetModuleHandleA(nullptr);\n'
                       '        const std::uintptr_t exeb = '
                       'reinterpret_cast<std::uintptr_t>(exe);\n'
                       '        for (int i = 0; i < 16; ++i) {\n'
                       '            std::uintptr_t v = 0; SIZE_T got = 0;\n'
                       '            if (ReadProcessMemory(GetCurrentProcess(), '
                       'reinterpret_cast<void*>(crsp + i*8), &v, 8, &got) && got == 8) {\n'
                       '                char fb[96];\n'
                       '                int fl = std::snprintf(fb, sizeof(fb),\n'
                       '                    "  stack[%d] = %p (exe off 0x%llx)\\n", i, '
                       '(void*)v, (unsigned long long)(v - exeb));\n'
                       '                if (fl > 0) WriteFile(hf, fb, (DWORD)fl, &wrote, nullptr);\n'
                       '            }\n'
                       '        }\n'
                       '        CloseHandle(hf);\n'
                       '    }\n'
                       '    return EXCEPTION_EXECUTE_HANDLER;\n'
                       '}\n#endif\n'
                       'int main(int argc, char** argv) {\n'
                       '#ifdef _WIN32\n'
                       '    AddVectoredExceptionHandler(1, recovered_crash_handler);\n'
                       '    SetUnhandledExceptionFilter(recovered_crash_handler);\n'
                       '#endif')
                save(main_path, src.replace(guard, new))
                print('recovered_main.cpp crash handler installed')
            else:
                print('recovered_main.cpp guard not found')
        else:
            print('recovered_main.cpp crash handler already present')

    # 8. FUN_0B0C970 aligned-free: native aborts with "Attempt to free nullptr
    #    pointer" when handed NULL (state drift hands it 0 from FUN_0471D80's
    #    clear loop); free(NULL) is legal, so no-op instead of fastfail.
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        if 'uint64_t FUN_0000000140B0C970(' in src and 'free(nullptr): no-op' not in src:
            src = src.replace(
                'uint64_t FUN_0000000140B0C970(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3) {\n',
                'uint64_t FUN_0000000140B0C970(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3) {\n'
                '    if (arg0 == 0) return 0;  // free(nullptr): no-op (native reports "Attempt to free nullptr" and aborts)\n',
                1)
            save(path, src)
            print('FUN_0B0C970 nullptr guard applied')
            break
    else:
        print('FUN_0B0C970 not found')

    # 9. FUN_05083D0: native is an LCG RNG (state*0x5DEECE66D+0xB & 0xFFFFFFFFFFFF
    #    + SSE float transform).  Recovery produced garbage hashing (constant
    #    shifted 16 bits, SSE dropped) that indexes a .rdata table with a huge
    #    value and SIGSEGVs.  No-op (returns 0).
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        if 'uint64_t FUN_00000001405083D0(' in src and 'LCG RNG' not in src:
            i = src.find('uint64_t FUN_00000001405083D0(')
            nl = src.find('\n', i)
            head = src[i:nl+1]
            src = src[:i] + ('uint64_t FUN_00000001405083D0(uint64_t arg0, uint64_t arg1, uint64_t arg2) {\n'
                             '    (void)arg0; (void)arg1; (void)arg2;\n'
                             '    return 0;  // native LCG RNG; recovery was garbage hashing; no-op\n')
            save(path, src)
            print('FUN_05083D0 no-op applied')
            break
    else:
        print('FUN_05083D0 not found')

    # 10. FUN_0508330: native ID-generator wrapper (call 0x508500, (eax<<16)|0x330E
    #    with GS check).  Recovery was the same garbage hashing.  No-op.
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        if 'uint64_t FUN_0000000140508330(' in src and 'ID generator wrapper' not in src:
            i = src.find('uint64_t FUN_0000000140508330(')
            nl = src.find('\n', i)
            head = src[i:nl+1]
            src = src[:i] + ('uint64_t FUN_0000000140508330(uint64_t arg0, uint64_t arg1, uint64_t arg3) {\n'
                             '    (void)arg0; (void)arg1; (void)arg3;\n'
                             '    return 0;  // native ID generator (call 0x508500, (eax<<16)|0x330E); recovery was garbage; no-op\n')
            save(path, src)
            print('FUN_0508330 no-op applied')
            break
    else:
        print('FUN_0508330 not found')

    # 11. FUN_041F210 allocator thunk: dispatch target returning 0 (calloc
    #    failure path in FUN_0B0D210) made FUN_003C670's rsi null; fall back to
    #    host allocation so callers always get a writable pointer.
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        if 'uint64_t FUN_000000014041F210(' in src and 'fallback' not in src:
            pat = re.compile(r'uint64_t FUN_000000014041F210\([^)]*\) \{(?:(?!\n\}\n).)*?\n\}\n', re.S)
            m = pat.search(src)
            if m:
                new = ('uint64_t FUN_000000014041F210(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {\n'
                       '    uint64_t rax = recovered_load<uint64_t>(5475174752);\n'
                       '    uint64_t r = 0;\n'
                       '    const std::uint64_t size = (a0 ? a0 : 1) + 16;  // allocator fallback (native calloc failure path returns 0)\n'
                       '    if (rax >= 5368709120ULL && rax < 5494044672ULL)\n'
                       '        r = recovered_dispatch(rax, a0, a1, a2, a3, 0, 0, 0, 0);\n'
                       '    else\n'
                       '        r = reinterpret_cast<std::uint64_t>(::operator new(size));\n'
                       '    if (r == 0 || r < 0x10000)\n'
                       '        r = reinterpret_cast<std::uint64_t>(::calloc(1, size));\n'
                       '    return r;\n}\n')
                save(path, src[:m.start()] + new + src[m.end():])
                print('FUN_041F210 fallback applied')
            else:
                print('FUN_041F210 pattern not matched')
            break
    else:
        print('FUN_041F210 not found')

    # 12. FUN_003C670: when the object lookup fails (rsi=0) the recovery's
    #    load(rsi+400) null-check reads mirror code bytes for low addresses and
    #    falls through to write [rsi+42..] (crash).  Native returns without
    #    writing; guard the strncpy write.
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        if 'FUN_000000014003C670(' in src and 'lookup/allocation failed' not in src:
            old = ('L0x14003c730:\n'
                   '    rcx = rsi + 42;\n'
                   '    r8 = (uint32_t)(256);\n'
                   '    rdx = r14;\n'
                   '    rax = FUN_0000000140386AF0(rsi + 42, r14, 256, r9);')
            new = ('L0x14003c730:\n'
                   '    if (rsi < 0x10000) return 0;  // lookup/allocation failed (rsi null/low): native returns without writing\n'
                   '    rcx = rsi + 42;\n'
                   '    r8 = (uint32_t)(256);\n'
                   '    rdx = r14;\n'
                   '    rax = FUN_0000000140386AF0(rsi + 42, r14, 256, r9);')
            if old in src:
                save(path, src.replace(old, new))
                print('FUN_003C670 low-rsi guard applied')
            else:
                print('FUN_003C670 strncpy block not matched (already patched?)')
            break
    else:
        print('FUN_003C670 not found')

    print('done')

if __name__ == '__main__':
    main()
