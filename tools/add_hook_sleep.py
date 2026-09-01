import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_main.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''    std::fprintf(stderr, "[IAT] 0x145d51518=%p 0x145d51508=%p 0x145d51510=%p\\n",'''
new = '''    std::fprintf(stderr, "[IAT] 0x145d4a230=%p 0x145d51518=%p 0x145d51508=%p 0x145d51510=%p\\n",
                 (void*)*(std::uintptr_t*)0x145d4a230ULL,
                 (void*)*(std::uintptr_t*)0x145d51518ULL,
                 (void*)*(std::uintptr_t*)0x145d51508ULL,
                 (void*)*(std::uintptr_t*)0x145d51510ULL);
    std::fprintf(stderr, "[IAT0] 0x145d4a230=%p 0x145d51518=%p 0x145d51508=%p 0x145d51510=%p\\n",
                 (void*)*(std::uintptr_t*)0x145d4a230ULL,
                 (void*)*(std::uintptr_t*)0x145d51518ULL,
                 (void*)*(std::uintptr_t*)0x145d51508ULL,
                 (void*)*(std::uintptr_t*)0x145d51510ULL);
    std::fprintf(stderr, "[IAT] 0x145d51518=%p 0x145d51508=%p 0x145d51510=%p\\n",'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('sleep slot read in hook added')
