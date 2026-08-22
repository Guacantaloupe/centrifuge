#!/usr/bin/env python3
"""Add dispatch-miss fallbacks to freshly recovered data-slot jump boards.

The decompiler now recovers `mov reg,[slot]; jmp *reg` boards as
    uint64_t FUN_xxx(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
        uint64_t rax = recovered_load<uint64_t>(SLOT);
        return recovered_dispatch(rax, rcx, rdx, r8, r9, 0, 0, 0, 0);
    }
with the ABI registers forwarded from the parameters.  At runtime the slot
holds whatever the image contains - for the Blender 5.2 allocator chain the
data-slot values are host addresses after import resolution, which the
dispatch table cannot match; a miss returns 0 and the caller dereferences
NULL.  Mirror the historical thunk_fix semantics: dispatch only targets
inside the image range, otherwise hand back host memory sized from a0
(= rcx, the caller's size register).  FUN_041F210 additionally gets the
historical +16 header and calloc re-try hardening.
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
    pat = re.compile(
        r'uint64_t (FUN_0000000140[0-9A-F]+)\(uint64_t arg0, uint64_t arg1, '
        r'uint64_t arg2, uint64_t arg3\) \{\n'
        r'(?:(?!\n\}\n).)*?recovered_load<uint64_t>\((\d+)\);\n'
        r'(?:(?!\n\}\n).)*?return recovered_dispatch\(rax, rcx, rdx, r8, r9, 0, 0, 0, 0\);\n'
        r'(?:(?!\n\}\n).)*?\n\}\n',
        re.S)
    fixed = 0
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        src = load(path)
        def repl(m):
            nonlocal fixed
            name, slot = m.group(1), int(m.group(2))
            fixed += 1
            if name == 'FUN_000000014041F210':
                body = ('uint64_t ' + name + '(uint64_t a0, uint64_t a1, '
                        'uint64_t a2, uint64_t a3) {\n'
                        '    uint64_t rax = recovered_load<uint64_t>(' + str(slot) + ');\n'
                        '    uint64_t r = 0;\n'
                        '    const std::uint64_t size = (a0 ? a0 : 1) + 16;\n'
                        '    if (rax >= 5368709120ULL && rax < 5494044672ULL)\n'
                        '        r = recovered_dispatch(rax, a0, a1, a2, a3, 0, 0, 0, 0);\n'
                        '    else\n'
                        '        r = reinterpret_cast<std::uint64_t>(::operator new(size));\n'
                        '    if (r == 0 || r < 0x10000)\n'
                        '        r = reinterpret_cast<std::uint64_t>(::calloc(1, size));\n'
                        '    return r;\n'
                        '}\n')
            else:
                body = ('uint64_t ' + name + '(uint64_t a0, uint64_t a1, '
                        'uint64_t a2, uint64_t a3) {\n'
                        '    uint64_t rax = recovered_load<uint64_t>(' + str(slot) + ');\n'
                        '    if (rax >= 5368709120ULL && rax < 5494044672ULL)\n'
                        '        return recovered_dispatch(rax, a0, a1, a2, a3, 0, 0, 0, 0);\n'
                        '    const std::uint64_t size = a0 ? a0 : 1;\n'
                        '    return reinterpret_cast<std::uint64_t>(::operator new(size));\n'
                        '}\n')
            return body
        new = pat.sub(repl, src)
        if new != src:
            save(path, new)
            print(path + ': ' + str(fixed) + ' boards patched (cumulative)')
    print('total boards patched: ' + str(fixed))

if __name__ == '__main__':
    main()
