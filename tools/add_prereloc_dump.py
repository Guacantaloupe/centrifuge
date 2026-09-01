import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''        const unsigned char* reloc =
            reinterpret_cast<const unsigned char*>(kRelocAddr);
        std::size_t pos = 0;'''
new = '''        const unsigned char* reloc =
            reinterpret_cast<const unsigned char*>(kRelocAddr);
        std::fprintf(stderr, "[RELOC-PRE] guard=%llx table0=%llx table1=%llx\\n",
                     (unsigned long long)*reinterpret_cast<std::uintptr_t*>(0x145d40858ULL),
                     (unsigned long long)*reinterpret_cast<std::uintptr_t*>(0x145d418c0ULL),
                     (unsigned long long)*reinterpret_cast<std::uintptr_t*>(0x145d418c8ULL));
        std::size_t pos = 0;'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('pre-reloc dump added')
