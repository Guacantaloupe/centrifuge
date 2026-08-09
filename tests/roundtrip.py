#!/usr/bin/env python3
"""Round-trip test: decompile demo_funcs.elf, wrap the output as C,
compile it, and check it produces the same results as the original C."""
import re, subprocess, sys, os

SPEC = "sleigh/riscv64.slaspec"
ELF = "tests/demo_funcs.elf"
GHR = "./build/ghra.exe"
FUNCS = [("compute", 0x80000000), ("max3", 0x8000001C), ("absdiff", 0x8000003C)]
VECTORS = {
    "compute": [(3, 90), (3, 95), (1, 97), (5, 0), (-3, 100), (2, 101), (7, 80), (0, 0)],
    "max3": [(1, 2, 3), (3, 2, 1), (2, 2, 2), (-1, -5, -3), (5, 5, 4), (0, -1, -2)],
    "absdiff": [(10, 3), (3, 10), (0, 0), (-5, 2), (5, -2), (-3, -8)],
}
SIGS = {
    "compute": "int64_t compute(int64_t a0, int64_t a1)",
    "max3": "int64_t max3(int64_t a0, int64_t a1, int64_t a2)",
    "absdiff": "int64_t absdiff(int64_t a0, int64_t a1)",
}

def decompile(name, addr):
    r = subprocess.run([GHR, "spec", SPEC, ELF, "decompile", hex(addr)],
                       capture_output=True, text=True, check=True)
    lines = [l for l in r.stdout.splitlines() if l.strip() and not l.startswith("// decompiled")]
    return "\n".join(lines)

body = {}
for name, addr in FUNCS:
    body[name] = decompile(name, addr)

# full RISC-V register file as locals (params copied in)
REG_DECL = (
    "int64_t zero=0, ra, sp, gp, tp, t0, t1, t2, s0, s1, "
    "a0=p0, a1=p1"
)
REG_DECL_2 = ", a2=p2"
REG_TAIL = (
    ", a3, a4, a5, a6, a7, "
    "s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, t3, t4, t5, t6;"
)

harness = ["#include <stdint.h>", "#include <stdio.h>", ""]
for name, addr in FUNCS:
    nargs = len(VECTORS[name][0])
    params = ", ".join("int64_t p%d" % i for i in range(nargs))
    decl = REG_DECL + (REG_DECL_2 if nargs > 2 else "") + REG_TAIL
    # declare SSA-versioned locals used in the body
    vers = sorted(set(re.findall(r'\b[a-z][a-z0-9]*_[0-9]+\b', body[name])))
    vers_decl = ("    int64_t " + ", ".join(vers) + ";") if vers else ""
    harness.append("int64_t %s(%s) {" % (name, params))
    harness.append("    " + decl)
    if vers_decl:
        harness.append(vers_decl)
    harness.append(body[name])
    harness.append("}")
    harness.append("")
harness.append("int main(void) {")
for name, addr in FUNCS:
    for vec in VECTORS[name]:
        args = ", ".join(str(v) for v in vec)
        harness.append('    printf("%%lld\\n", (long long)%s(%s));' % (name, args))
harness.append("    return 0;")
harness.append("}")

open("tests/dec_harness.c", "w").write("\n".join(harness) + "\n")

# original versions for ground truth
orig = ["#include <stdio.h>", ""]
orig += open("tests/demo_funcs.c").read().splitlines()
orig.append("")
orig.append("int main(void) {")
for name, addr in FUNCS:
    for vec in VECTORS[name]:
        args = ", ".join(str(v) for v in vec)
        orig.append('    printf("%%lld\\n", (long long)%s(%s));' % (name, args))
orig.append("    return 0;")
orig.append("}")
open("tests/orig_harness.c", "w").write("\n".join(orig) + "\n")

cc = "gcc"
for src, exe in [("tests/dec_harness.c", "tests/dec_test.exe"),
                 ("tests/orig_harness.c", "tests/orig_test.exe")]:
    r = subprocess.run([cc, "-O0", "-o", exe, src], capture_output=True, text=True)
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
