#!/usr/bin/env python3
"""Upgrade v0 thunks (void FUN_xxx(uint32_t argN) { rax = load(slot); ...;
return; }) to v2 register-forwarding thunks, and rewrite call sites to pass
live registers (rcx, rdx, r8, r9) exactly like the native data-slot jmp
thunks do.  Run after thunk_fix.py / thunk_fix2.py.

Usage: python thunk_fix3.py <project-src-dir>
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
    # v0 thunk: void FUN_0000000140XXXXXX(uint32_t argN) { ... load(slot) ... return; }
    defn_pat = re.compile(
        r'void (FUN_0000000140[0-9A-F]{6,7})\(uint32_t arg\d\) \{\n'
        r'    uint64_t rax = 0, r\d = 0;\n'
        r'    r\d = \(uint64_t\)\(uintptr_t\)arg\d;\n'
        r'    rax = recovered_load<uint64_t>\((\d+)\);\n'
        r'    r\d = \(uint32_t\)\(0\);\n'
        r'    return;\n'
        r'\}\n')
    names = {}
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        before = len(names)
        def repl(m):
            name, slot = m.group(1), int(m.group(2))
            names[name] = slot
            return ('uint64_t ' + name +
                    '(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {\n'
                    '    uint64_t rax = recovered_load<uint64_t>(' + str(slot) + ');\n'
                    '    if (rax >= 5368709120ULL && rax < 5494044672ULL)\n'
                    '        return recovered_dispatch(rax, a0, a1, a2, a3, 0, 0, 0, 0);\n'
                    '    const std::uint64_t size = a0 ? a0 : 1;\n'
                    '    return reinterpret_cast<std::uint64_t>(::operator new(size));\n'
                    '}\n')
        new = defn_pat.sub(repl, src)
        if new != src:
            save(path, new)
            print(path + ': ' + str(len(names) - before) + ' v0 thunks upgraded')
    if not names:
        print('no v0 thunks found')
        return
    alt = '|'.join(re.escape(n) for n in names)
    call_pat = re.compile(r'(?<![A-Z0-9_])(?:' + alt + r')\(r9\);')
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        if path.endswith('recovered_metadata.cpp'):
            continue
        src = load(path)
        new = call_pat.sub(lambda m: 'rax = ' + m.group(0).replace('(r9);', '(rcx, rdx, r8, r9);'), src)
        if new != src:
            save(path, new)
            print(path + ': call sites pass registers')
    md_path = src_dir + '/recovered_metadata.cpp'
    md = load(md_path)
    case_pat = re.compile(r'return (' + alt + r')\(static_cast<uint32_t>\(a\d\)\);')
    md_new = case_pat.sub(lambda m: 'return ' + m.group(1) + '(a0, a1, a2, a3);', md)
    if md_new != md:
        save(md_path, md_new)
        print(md_path + ': dispatch cases pass registers')
    hpp_path = 'include/recovered.hpp'
    hpp = load(hpp_path)
    changed = 0
    for n in names:
        old = 'void ' + n + '(uint32_t);'
        if old in hpp:
            hpp = hpp.replace(
                old, 'uint64_t ' + n +
                '(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);')
            changed += 1
    if changed:
        save(hpp_path, hpp)
        print(hpp_path + ': ' + str(changed) + ' declarations upgraded')
    print('done')

if __name__ == '__main__':
    main()
