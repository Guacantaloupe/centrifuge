#!/usr/bin/env python3
"""Round-trip test: decompile functions from real compiler output, wrap the
output as C, compile it, and check it produces the same results as the
original C."""
import re, subprocess, sys, os

SPEC = "sleigh/riscv64.slaspec"
ELF = "tests/real_riscv2.elf"
GHR = "./build/centrifuge.exe"
CC = "gcc"

FUNCS = [
    # name, addr, argc, kind ("plain" | "array"), vectors
    ("fib",       0x80000040, 1, "plain", list(range(0, 11))),
    ("sum_array", 0x800003E4, 2, "array", [[1, 2, 3, 4], [5], [], [7, -1, 3]]),
]

# all decompiled functions take 8 register args (calls pass a0..a7)
SIG = "int64_t %s(int64_t p0, int64_t p1, int64_t p2, int64_t p3, int64_t p4, int64_t p5, int64_t p6, int64_t p7)"
REG_DECL = (
    "int64_t zero=0, ra, sp, gp, tp, t0, t1, t2, s0, s1, "
    "a0=p0, a1=p1, a2=p2, a3=p3, a4=p4, a5=p5, a6=p6, a7=p7, "
    "s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, t3, t4, t5, t6;"
)

def decompile(name, addr):
    r = subprocess.run([GHR, "spec", SPEC, ELF, "decompile", hex(addr)],
                       capture_output=True, text=True, check=True)
    lines = [l for l in r.stdout.splitlines()
             if l.strip() and not l.startswith("// decompiled")]
    return "\n".join(lines)

body = {}
for name, addr, *_ in FUNCS:
    body[name] = decompile(name, addr)

harness = ["#include <stdint.h>", "#include <stdio.h>", ""]
# forward declarations (self-recursion)
harness.append("int64_t fib(int64_t p0, int64_t p1, int64_t p2, int64_t p3, int64_t p4, int64_t p5, int64_t p6, int64_t p7);")
harness.append("int64_t sum_array(int64_t p0, int64_t p1, int64_t p2, int64_t p3, int64_t p4, int64_t p5, int64_t p6, int64_t p7);")
harness.append("")

for name, addr, argc, kind, vectors in FUNCS:
    decl = REG_DECL
    vers = sorted(set(re.findall(r'\b(?:local_m\d+|local_\d+|[a-z][a-z0-9]*_\d+)\b', body[name])))
    vers = [v for v in vers if not re.match(r'^(a0|a1|a2|zero|sp|ra)$', v)]
    vers_decl = ("    int64_t " + ", ".join(vers) + ";") if vers else ""
    harness.append(SIG % name + " {")
    harness.append("    " + decl)
    if vers_decl:
        harness.append(vers_decl)
    harness.append(body[name])
    harness.append("}")
    harness.append("")

harness.append("int main(void) {")
for name, addr, argc, kind, vectors in FUNCS:
    if kind == "array":
        for i, arr in enumerate(vectors):
            decl = "int a%d[%d] = {%s};" % (i, len(arr), ", ".join(str(x) for x in arr))
            harness.append("    " + decl)
            harness.append('    printf("%%lld\\n", (long long)sum_array((int64_t)a%d, %d, 0, 0, 0, 0, 0, 0));' % (i, len(arr)))
    else:
        for vec in vectors:
            vec = vec if isinstance(vec, tuple) else (vec,)
            args = ", ".join(str(v) for v in vec)
            pad = 8 - len(vec)
            if pad > 0:
                args += ", " + ", ".join(["0"] * pad)
            harness.append('    printf("%%lld\\n", (long long)%s(%s));' % (name, args))
harness.append("    return 0;")
harness.append("}")
open("tests/dec_harness.c", "w").write("\n".join(harness) + "\n")

# original ground truth (drop the source's main - it has nested braces)
src = open("tests/real_riscv2.c").read()
i = src.find('int main')
if i >= 0:
    src = src[:i]
orig = ["#include <stdio.h>", ""] + src.splitlines()
orig.append("")
orig.append("int main(void) {")
for name, addr, argc, kind, vectors in FUNCS:
    if kind == "array":
        for i, arr in enumerate(vectors):
            decl = "int a%d[%d] = {%s};" % (i, len(arr), ", ".join(str(x) for x in arr))
            orig.append("    " + decl)
            orig.append('    printf("%%lld\\n", (long long)sum_array(a%d, %d));' % (i, len(arr)))
    else:
        for vec in vectors:
            vec = vec if isinstance(vec, tuple) else (vec,)
            args = ", ".join(str(v) for v in vec)
            orig.append('    printf("%%lld\\n", (long long)%s(%s));' % (name, args))
orig.append("    return 0;")
orig.append("}")
open("tests/orig_harness.c", "w").write("\n".join(orig) + "\n")

for src, exe in [("tests/dec_harness.c", "tests/dec_test.exe"),
                 ("tests/orig_harness.c", "tests/orig_test.exe")]:
    r = subprocess.run([CC, "-O0", "-o", exe, src], capture_output=True, text=True)
    if r.returncode != 0:
        print("COMPILE FAIL:", src)
        print(r.stderr)
        sys.exit(1)

d = subprocess.run(["./tests/dec_test.exe"], capture_output=True, text=True, check=True).stdout
o = subprocess.run(["./tests/orig_test.exe"], capture_output=True, text=True, check=True).stdout
dl, ol = d.splitlines(), o.splitlines()
if dl == ol:
    print("ROUND-TRIP OK: decompiled output matches original C on %d test vectors" % len(dl))
else:
    print("MISMATCH (%d vs %d lines)" % (len(dl), len(ol)))
    for i, (a, b) in enumerate(zip(dl, ol)):
        if a != b:
            print("  vector %d: decompiled=%s original=%s" % (i, a, b))
    sys.exit(1)
