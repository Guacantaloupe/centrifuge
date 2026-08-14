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
"""
import glob, io, re, sys

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

    print('done')

if __name__ == '__main__':
    main()
