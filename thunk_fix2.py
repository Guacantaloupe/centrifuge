#!/usr/bin/env python3
"""Upgrade v1 thunk output (uint64_t FUN_xxx(void) + 0-arg dispatch) to v2
(4-arg register-forwarding thunks).  Run after thunk_fix.py v1.

Usage: python thunk_fix2.py <project-src-dir>
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
    name_pat = r'FUN_0000000140[0-9A-F]{6,7}'
    defn_pat = re.compile(
        r'uint64_t (' + name_pat + r')\(void\) \{\n'
        r'    uint64_t rax = recovered_load<uint64_t>\((\d+)\);\n'
        r'    if \(rax >= 5368709120ULL && rax < 5494044672ULL\)\n'
        r'        return recovered_dispatch\(rax, 0, 0, 0, 0, 0, 0, 0\);\n'
        r'    return reinterpret_cast<std::uint64_t>\(::operator new\(4096\)\);\n'
        r'\}\n')
    fixed = 0
    names = []
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        before = fixed
        def repl(m):
            nonlocal fixed
            name, slot = m.group(1), int(m.group(2))
            fixed += 1
            names.append(name)
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
            print(path + ': ' + str(fixed - before) + ' thunks upgraded to v2')
    if not names:
        print('no v1 thunks found')
        return
    call_pat = re.compile(r'(?<!void )(?<![A-Z0-9_])(' + '|'.join(
        re.escape(n) for n in names) + r')\(\);')
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        if path.endswith('recovered_metadata.cpp'):
            continue
        src = load(path)
        new = call_pat.sub(
            lambda m: 'rax = ' + m.group(1) + '(rcx, rdx, r8, r9);', src)
        if new != src:
            save(path, new)
            print(path + ': call sites pass registers')
    md_path = src_dir + '/recovered_metadata.cpp'
    md = load(md_path)
    case_pat = re.compile(r'return (' + '|'.join(re.escape(n) for n in names) +
                          r')\(\);')
    md_new = case_pat.sub(
        lambda m: 'return ' + m.group(1) + '(a0, a1, a2, a3);', md)
    if md_new != md:
        save(md_path, md_new)
        print(md_path + ': dispatch cases pass registers')
    hpp_path = 'include/recovered.hpp'
    hpp = load(hpp_path)
    changed = 0
    for n in names:
        old = 'uint64_t ' + n + '(void);'
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
