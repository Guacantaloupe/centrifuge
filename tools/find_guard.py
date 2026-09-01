import sys, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
src = open(r'build-recheck54\src\recovered_metadata.cpp', encoding='utf-8').read()
for m in re.finditer(r'\{"([^"]+)", "([^"]+)"[^}]*?(\d+)ULL', src):
    dll, name, iat = m.group(1), m.group(2), int(m.group(3))
    if iat == 0x145d40858:
        print('EXACT', dll, name, hex(iat))
    if abs(iat - 0x145d40858) < 0x60:
        print('near', hex(iat), dll, name)
