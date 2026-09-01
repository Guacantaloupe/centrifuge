import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''        if (tlsArray && runtime_tls_block.empty())
            runtime_tls_block.assign(runtime_tls_template);
        if (tlsArray && !runtime_tls_block.empty())
            tlsArray[kImageTlsIndex] = runtime_tls_block.data();'''
new = '''        if (tlsArray && runtime_tls_block.empty())
            runtime_tls_block = runtime_tls_template;
        if (tlsArray && !runtime_tls_block.empty())
            tlsArray[kImageTlsIndex] =
                reinterpret_cast<void*>(runtime_tls_block.data());'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('fixed')
