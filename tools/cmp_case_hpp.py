import re, sys

meta = open('build-recheck52/src/recovered_metadata.cpp', encoding='utf-8-sig').read()
hpp = open('build-recheck52/include/recovered.hpp', encoding='utf-8-sig').read()

case_names = set(re.findall(r'case (\d+)ULL:', meta))
hpp_names = set(re.findall(r'^[a-z0-9_]+ (FUN_[0-9A-F]+)', hpp, re.M))

# case address -> FUN name mapping from metadata lines
case_to_fun = {}
for m in re.finditer(r'case (\d+)ULL:\n\s+(?:return static_cast<std::uint64_t>\()?([A-Za-z0-9_]+)\(', meta):
    case_to_fun.setdefault(int(m.group(1)), m.group(2))

print('cases:', len(case_names), 'hpp decls:', len(hpp_names))
print()
print('=== cases whose function has no hpp declaration ===')
n = 0
for addr in sorted(int(a) for a in case_names):
    fun = case_to_fun.get(addr, '???')
    if fun not in hpp_names:
        print('  case 0x%x -> %s (missing decl)' % (addr, fun))
        n += 1
print('total missing decl:', n)
print()
print('=== sample of decls without case (extra decls) ===')
decls = re.findall(r'^[a-z0-9_]+ (FUN_[0-9A-F]+)\(', hpp, re.M)
extra = [d for d in decls if d not in case_to_fun.values()]
print('extra decls:', len(extra))
