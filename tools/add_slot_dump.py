import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_main.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''    std::fprintf(stderr, "\\n");
    return EXCEPTION_CONTINUE_SEARCH;'''
new = '''    std::fprintf(stderr, "\\n");
    std::fprintf(stderr, "[SLOT] sleep=%p guard=%p\\n",
                 (void*)*(std::uintptr_t*)0x145d4a230ULL,
                 (void*)*(std::uintptr_t*)0x145d40858ULL);
    return EXCEPTION_CONTINUE_SEARCH;'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('slot dump added to hook')
