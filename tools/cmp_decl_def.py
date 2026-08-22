import glob, re

hpp = open('build-recheck52/include/recovered.hpp', encoding='utf-8-sig').read()
decls = set(re.findall(r'^[a-z0-9_]+ (FUN_[0-9A-Fa-f]+)\(', hpp, re.M))

defs = set()
for p in glob.glob('build-recheck52/src/recovered_*.cpp'):
    if re.search(r'(metadata|main|runtime|external)', p): continue
    src = open(p, encoding='utf-8-sig').read()
    defs |= set(re.findall(r'^[a-z0-9_]+ (FUN_[0-9A-Fa-f]+)\(', src, re.M))

print('decls:', len(decls), 'defs:', len(defs))
missing_def = sorted(decls - defs)
print('declared but NOT defined:', len(missing_def))
for n in missing_def[:20]:
    print('  ', n)
orphan_def = sorted(defs - decls)
print('defined but NOT declared:', len(orphan_def))
for n in orphan_def[:10]:
    print('  ', n)
