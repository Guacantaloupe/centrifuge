import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_main.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 删除 [RELOC] 打印块 (hook 里的)
old = '''    std::fprintf(stderr, "[RELOC] ");
    for (std::size_t i = 0; i < 8; ++i)
        std::fprintf(stderr, "%02x", reinterpret_cast<unsigned char*>(0x1477A0000ULL)[i]);
    std::fprintf(stderr, " | ");
    for (std::size_t i = 0; i < 8; ++i)
        std::fprintf(stderr, "%02x", reinterpret_cast<unsigned char*>(0x1477A0000ULL + 8)[i]);
    std::fprintf(stderr, "\\n");
'''
assert old in src
src = src.replace(old, '')
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('RELOC dump removed from hook')
