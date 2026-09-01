import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''    {
        constexpr std::uintptr_t kImageBase = 0x140000000ULL;
        constexpr std::uintptr_t kRelocAddr = 0x1477A0000ULL;
        constexpr std::size_t kRelocSize = 0x4578CULL;
        const unsigned char* reloc =
            reinterpret_cast<const unsigned char*>(kRelocAddr);'''
new = '''    {
        constexpr std::uintptr_t kImageBase = 0x140000000ULL;
        // Locate the .reloc region dynamically instead of hard-coding
        // its address; the region table is the source of truth.
        std::uintptr_t kRelocAddr = 0;
        std::size_t kRelocSize = 0;
        for (const auto& region : runtime_regions) {
            if (region.name == ".reloc") {
                kRelocAddr = region.address;
                kRelocSize = region.bytes.size();
                break;
            }
        }
        if (!kRelocAddr || kRelocSize < 8) return false;
        const unsigned char* reloc =
            reinterpret_cast<const unsigned char*>(kRelocAddr);'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('reloc addr now dynamic')
