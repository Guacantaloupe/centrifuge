import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''            bool mapped = reservation == reinterpret_cast<void*>(reserveBegin);'''
new = '''            bool mapped = reservation == reinterpret_cast<void*>(reserveBegin);
            std::fprintf(stderr, "[MAP] reserve 0x%llx+0x%llx -> %p\\n",
                         (unsigned long long)reserveBegin,
                         (unsigned long long)(reserveEnd - reserveBegin),
                         reservation);'''
assert old in src
src = src.replace(old, new)
# commit 循环后打印每个 region 状态
old2 = '''            if (!committed) { mapped = false; break; }'''
new2 = '''            if (!committed) { mapped = false; std::fprintf(stderr, "[MAP] commit FAIL 0x%llx+0x%llx\\n", (unsigned long long)pageBegin, (unsigned long long)(pageEnd - pageBegin)); break; }
            std::fprintf(stderr, "[MAP] commit 0x%llx+0x%llx\\n", (unsigned long long)pageBegin, (unsigned long long)(pageEnd - pageBegin));'''
assert old2 in src
src = src.replace(old2, new2)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('map diagnostics added')
