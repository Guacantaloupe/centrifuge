import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''            if (mapped) {
                runtime_fixed_image = reservation;
                for (auto& region : loaded) {'''
new = '''            std::fprintf(stderr, "[MAP] reservation=%p mapped=%d regions=%zu\\n",
                         reservation, mapped ? 1 : 0, loaded.size());
            if (mapped) {
                runtime_fixed_image = reservation;
                for (auto& region : loaded) {'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('map status dump added')
