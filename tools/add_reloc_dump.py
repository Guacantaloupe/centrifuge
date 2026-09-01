import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''            pos += blockSize;
        }
    }

    // Write resolved import addresses back into the fixed-image IAT'''
new = '''            pos += blockSize;
        }
        std::fprintf(stderr, "[RELOC-OK] bytes=%llu hdr4=%llx guard=%llx table0=%llx table1=%llx\\n",
                     (unsigned long long)pos,
                     (unsigned long long)*reinterpret_cast<std::uint32_t*>(0x140000000ULL + 4),
                     (unsigned long long)*reinterpret_cast<std::uintptr_t*>(0x145d40858ULL),
                     (unsigned long long)*reinterpret_cast<std::uintptr_t*>(0x145d418c0ULL),
                     (unsigned long long)*reinterpret_cast<std::uintptr_t*>(0x145d418c8ULL));
    }

    // Write resolved import addresses back into the fixed-image IAT'''
assert old in src, 'anchor missing'
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('reloc post-state dump added')
