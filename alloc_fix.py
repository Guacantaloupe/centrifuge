#!/usr/bin/env python3
"""Replace recovered allocator bodies in recovered_14.cpp with host allocation.

The recovered allocators (0x140B0CCE0 / 0x140B0D210 / 0x140B0D4E0) execute
complex simulated stack/heap logic that depends on recovered global state and
can abort (0x140B0D4E0 calls the CRT abort import).  For the startup path they
must simply hand back writable host memory sized from arg0.
"""
import io, re, sys

def load(p):
    with open(p, 'rb') as f:
        return f.read().decode('utf-8-sig')

def save(p, s):
    with open(p, 'w', encoding='utf-8', newline='') as f:
        f.write(s)

def main():
    path = 'src/recovered_14.cpp'
    src = load(path)
    names = ['FUN_0000000140B0CCE0', 'FUN_0000000140B0D210',
             'FUN_0000000140B0D4E0']
    for name in names:
        i = src.find('uint64_t ' + name + '(')
        if i < 0:
            print('!! missing', name)
            continue
        j = src.find('{', i)
        depth = 0
        k = j
        while k < len(src):
            if src[k] == '{':
                depth += 1
            elif src[k] == '}':
                depth -= 1
                if depth == 0:
                    break
            k += 1
        replacement = ('uint64_t ' + name +
                       '(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3) {\n'
                       '    (void)arg1; (void)arg2; (void)arg3;\n'
                       '    const std::uint64_t size = arg0 ? arg0 : 1;\n'
                       '    return reinterpret_cast<std::uint64_t>(::operator new(size));\n'
                       '}\n')
        src = src[:i] + replacement + src[k + 1:]
        print('replaced', name)
    save(path, src)
    print('done')

if __name__ == '__main__':
    main()
