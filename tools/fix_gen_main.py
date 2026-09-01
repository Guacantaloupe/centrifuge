import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'src\project_recovery.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '<< "}\\n"\n               << "#endif\\n"\n               << "    std::fprintf(stderr, \\"\\");  // warm CRT stderr so exit cleanup cannot corrupt the heap\\n"'
new = '<< "}\\n"\n               << "#endif\\n"\n               << "int main(int argc, char** argv) {\\n"\n               << "    std::fprintf(stderr, \\"\\");  // warm CRT stderr so exit cleanup cannot corrupt the heap\\n"'
assert old in src, 'anchor missing'
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('main() header restored in generator')
