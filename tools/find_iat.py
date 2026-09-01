import re, sys
src = open(r'build-recheck53\src\recovered_metadata.cpp', encoding='utf-8').read()
for m in re.finditer(r'\{"([^"]+)", "([^"]+)"[^}]*?(\d+)ULL', src):
    dll, name, iat = m.group(1), m.group(2), int(m.group(3))
    if abs(iat - 0x145d51518) < 0x400:
        print(hex(iat), dll, name)
