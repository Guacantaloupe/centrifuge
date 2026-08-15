#!/usr/bin/env python3
"""Upgrade FUN_041F200 (v0 thunk with (uint32_t arg1) signature, ~900 call
sites passing only rdx) to v2 register-forwarding thunk.  The native
data-slot jmp thunk tail-passes ALL caller registers; call sites must pass
(rcx, rdx, r8, r9).

Usage: python thunk_fix4.py <project-src-dir>
"""
import glob, io, re, sys

def load(p):
    with open(p, 'rb') as f:
        return f.read().decode('utf-8-sig')

def save(p, s):
    with open(p, 'w', encoding='utf-8', newline='') as f:
        f.write(s)

NAME = 'FUN_000000014041F200'
SLOT = 5475174720  # 0x1465889C0

def main():
    src_dir = sys.argv[1] if len(sys.argv) > 1 else 'src'
    # 1. definition
    defn_pat = re.compile(
        r'void ' + NAME + r'\(uint32_t arg1\) \{[^}]*\}\s*')
    new_defn = ('uint64_t ' + NAME +
                '(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {\n'
                '    uint64_t rax = recovered_load<uint64_t>(' + str(SLOT) + ');\n'
                '    if (rax >= 5368709120ULL && rax < 5494044672ULL)\n'
                '        return recovered_dispatch(rax, a0, a1, a2, a3, 0, 0, 0, 0);\n'
                '    const std::uint64_t size = a0 ? a0 : 1;\n'
                '    return reinterpret_cast<std::uint64_t>(::operator new(size));\n'
                '}\n')
    done = 0
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        new, n = defn_pat.subn(new_defn, src)
        if n:
            save(path, new)
            print(path + ': definition upgraded')
            done += 1
            break
    if not done:
        print('definition not found (already upgraded?)')
    # 2. call sites
    call_pat = re.compile(r'(?<![A-Z0-9_])' + NAME + r'\((rdx|1)\);')
    count = 0
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        if path.endswith('recovered_metadata.cpp'):
            continue
        src = load(path)
        new, n = call_pat.subn(
            lambda m: 'rax = ' + NAME + '(rcx, rdx, r8, r9);', src)
        if n:
            save(path, new)
            count += n
    print('call sites rewritten:', count)
    # 3. metadata dispatch case
    md_path = src_dir + '/recovered_metadata.cpp'
    md = load(md_path)
    md_new = md.replace(
        'return ' + NAME + '(static_cast<uint32_t>(a0));',
        'return ' + NAME + '(a0, a1, a2, a3);')
    if md_new != md:
        save(md_path, md_new)
        print(md_path + ': dispatch case upgraded')
    # 4. hpp declaration
    hpp_path = 'include/recovered.hpp'
    hpp = load(hpp_path)
    hpp_new = hpp.replace(
        'void ' + NAME + '(uint32_t arg1);',
        'uint64_t ' + NAME +
        '(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);')
    if hpp_new != hpp:
        save(hpp_path, hpp_new)
        print(hpp_path + ': declaration upgraded')
    print('done')

if __name__ == '__main__':
    main()
