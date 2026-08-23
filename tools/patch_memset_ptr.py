import glob, re
# patch memset/memcpy 类 import 包装：第 1 参（指针）翻译成宿主地址
for f in glob.glob('build-recheck52/src/recovered_*.cpp'):
    t = open(f, encoding='utf-8-sig', errors='replace').read()
    orig = t
    # memset 包装形态：return import_...memset...(rcx, rdx, r8, ...);
    t = re.sub(
        r'(L0x[0-9a-f]+:\n)(    return import_[A-Za-z0-9_]*memset[A-Za-z0-9_]*\(rcx, rdx, r8, r9[^;]*\);)',
        r'\1    if (rcx) rcx = (std::uint64_t)(uintptr_t)recovered_translate_address(rcx, 1);\n\2',
        t)
    if t != orig:
        open(f, 'w', encoding='utf-8-sig').write(t)
        print('patched', f)
