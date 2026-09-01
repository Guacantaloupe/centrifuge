import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
gen = io.open(r'src\project_recovery.cpp', encoding='utf-8', errors='replace').read()
i = gen.find('mainSource << "#include')
print('at', i)
print(gen[i:i+900])
