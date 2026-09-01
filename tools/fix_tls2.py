import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''        auto* teb = NtCurrentTeb();
        auto** tlsArray = *reinterpret_cast<PVOID***>(
            reinterpret_cast<unsigned char*>(teb) + 0x58);'''
new = '''        auto* teb = NtCurrentTeb();
        auto* tlsArray = *reinterpret_cast<PVOID**>(
            reinterpret_cast<unsigned char*>(teb) + 0x58);'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('tlsArray type fixed')
