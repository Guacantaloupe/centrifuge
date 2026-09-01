import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_metadata.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''    std::fprintf(stderr, "[PEHDR90] %02x %02x %02x %02x %02x %02x %02x %02x\\n",
                     hdr[0x90], hdr[0x91], hdr[0x92], hdr[0x93], hdr[0x94], hdr[0x95], hdr[0x96], hdr[0x97]);
    }'''
new = '''    std::fprintf(stderr, "[PEHDR90] %02x %02x %02x %02x %02x %02x %02x %02x\\n",
                     hdr[0x90], hdr[0x91], hdr[0x92], hdr[0x93], hdr[0x94], hdr[0x95], hdr[0x96], hdr[0x97]);
    }
    {
        std::fprintf(stderr, "[TLSARR] cb@0x145d41900: %p %p %p %p\\n",
                     (void*)*(std::uintptr_t*)0x145d41900ULL,
                     (void*)*(std::uintptr_t*)0x145d41908ULL,
                     (void*)*(std::uintptr_t*)0x145d41910ULL,
                     (void*)*(std::uintptr_t*)0x145d41918ULL);
        std::fprintf(stderr, "[TBL] 0x145d418c0: %p %p %p %p\\n",
                     (void*)*(std::uintptr_t*)0x145d418c0ULL,
                     (void*)*(std::uintptr_t*)0x145d418c8ULL,
                     (void*)*(std::uintptr_t*)0x145d418d0ULL,
                     (void*)*(std::uintptr_t*)0x145d418d8ULL);
    }'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('TLS array + table dump added')
