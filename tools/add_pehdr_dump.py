import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_metadata.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''    std::fprintf(stderr, "[PE] e_lfanew=%u entryRva=%u optMagic=%u\\n",
                 *reinterpret_cast<unsigned*>(0x140000000ULL + 0x3C),
                 *reinterpret_cast<unsigned*>(0x140000000ULL + 0x3C + 24 + 16),
                 *reinterpret_cast<unsigned short*>(0x140000000ULL + 0x3C + 24));'''
new = '''    std::fprintf(stderr, "[PE] e_lfanew=%u entryRva=%u optMagic=%u\\n",
                 *reinterpret_cast<unsigned*>(0x140000000ULL + 0x3C),
                 *reinterpret_cast<unsigned*>(0x140000000ULL + 0x3C + 24 + 16),
                 *reinterpret_cast<unsigned short*>(0x140000000ULL + 0x3C + 24));
    {
        const unsigned char* hdr = reinterpret_cast<const unsigned char*>(0x140000000ULL);
        std::fprintf(stderr, "[PEHDR] %02x %02x %02x %02x %02x %02x %02x %02x | %02x %02x %02x %02x %02x %02x %02x %02x\\n",
                     hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7],
                     hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15]);
        std::fprintf(stderr, "[PEHDR90] %02x %02x %02x %02x %02x %02x %02x %02x\\n",
                     hdr[0x90], hdr[0x91], hdr[0x92], hdr[0x93], hdr[0x94], hdr[0x95], hdr[0x96], hdr[0x97]);
    }'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('PE header raw dump added')
