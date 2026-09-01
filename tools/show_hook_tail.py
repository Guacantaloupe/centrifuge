import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
gen = io.open(r'src\project_recovery.cpp', encoding='utf-8', errors='replace').read()
i = gen.find('static LONG WINAPI recovered_exception_hook')
seg = gen[i:i+2500]
print(seg[900:2500])
