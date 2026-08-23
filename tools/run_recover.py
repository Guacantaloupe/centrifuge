import subprocess, sys, time
target = sys.argv[1]
outdir = sys.argv[2]
budget = sys.argv[3]
exe = r'build-fresh\centrifuge.exe'
args = [exe, 'spec', 'sleigh\\x86-64.slaspec', target, 'recover-project', outdir, 'win64', budget]
p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1,
                     universal_newlines=True)
start = time.time()
for line in p.stdout:
    print('[%5.1fs] %s' % (time.time() - start, line.rstrip()), flush=True)
p.wait()
print('exit=%d total=%.1fs' % (p.returncode, time.time() - start), flush=True)
