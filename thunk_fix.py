#!/usr/bin/env python3
"""Batch-upgrade data-slot thunks in freshly recovered Blender sources.

Recovered thunks of the form
    void FUN_0000000140XXXXXXX(void) {
        uint64_t rax = 0;
        rax = recovered_load<uint64_t>(SLOT);
        return;
    }
are the recovery of `mov reg,[rip+slot]; jmp *reg` jump boards.  The
decompiler emits them as void and drops the tail call.  Rewrite them to take
the four ABI argument registers, load the slot and dispatch to the slot target
with those arguments (or return host memory), upgrade call sites so they pass
the live registers and capture the value, and fix declarations + dispatch
cases.  Passing the caller's live registers matters: native thunks forward the
caller's rcx/rdx/r8/r9 untouched (e.g. allocators called with their size in
rcx), and a 0-argument dispatch allocates 1 byte, corrupting the heap.

Usage: python thunk_fix.py <project-src-dir>
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
        r'void (' + name_pat + r')\(void\) \{\n'
        r'    uint64_t rax = 0;\n'
        r'    rax = recovered_load<uint64_t>\((\d+)\);\n'
        r'    return;\n'
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
            print(path + ': ' + str(fixed - before) + ' thunks upgraded')
    if not names:
        print('no thunks found')
        return
    # Call sites: `FUN_xxx();` -> `rax = FUN_xxx(rcx, rdx, r8, r9);`
    # (registers are live locals in the recovered body at the call point).
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
    # Dispatch cases: `FUN_xxx(); return 0;` -> `return FUN_xxx(a0,a1,a2,a3);`
    md_path = src_dir + '/recovered_metadata.cpp'
    md = load(md_path)
    case_pat = re.compile(r'(' + '|'.join(re.escape(n) for n in names) +
                          r')\(\); return 0;')
    md_new = case_pat.sub(
        lambda m: 'return ' + m.group(1) + '(a0, a1, a2, a3);', md)
    if md_new != md:
        save(md_path, md_new)
        print(md_path + ': dispatch cases pass registers')
    # Declarations
    hpp_path = 'include/recovered.hpp'
    hpp = load(hpp_path)
    changed = 0
    for n in names:
        old = 'void ' + n + '(void);'
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
