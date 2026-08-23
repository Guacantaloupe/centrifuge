import re
t = open('build-recheck52/src/recovered_metadata.cpp', encoding='utf-8-sig', errors='replace').read()
m = re.search(r'recovered_image_regions\[\] = \{(.*?)\};', t, re.S)
for line in m.group(1).strip().splitlines():
    line = line.strip()
    if not line:
        continue
    m2 = re.match(r'\{"([^"]+)", (\d+)ULL, (\d+)ULL', line)
    if m2:
        name, addr, size = m2.group(1), int(m2.group(2)), int(m2.group(3))
        print('%-8s @ 0x%-12x size 0x%-8x end 0x%x' % (name, addr, size, addr + size))
