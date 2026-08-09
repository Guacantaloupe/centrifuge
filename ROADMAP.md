# Roadmap — Centrifuge (离心机): merging Ghidra + angr in C++17

One foundation (loaders → spec-driven disassembly → p-code), two analysis
rotors: static decompilation (Ghidra) and symbolic exploration (angr).
No external decoders/libraries — every layer is written from scratch.

## ✅ v0.1 — Foundation
- Memory model, ELF32/64 + PE32/PE32+ loaders, CLI

## ✅ v0.2 — 100% C++ decoders
- Hand-written x86/x86-64 + RISC-V decoders (Capstone removed)
- Validated vs GNU objdump: notepad.exe / kernel32.dll, 0 errors

## ✅ v0.3 — SLEIGH-lite spec engine
- p-code IR + interpreter (constant folding + concrete semantics)
- Spec parser: spaces, registers, tokens (composed bit fields), attach
  variables, constructors with first-match patterns; multi-token support;
  x86 prefix/ModRM magic terms
- Language modules: `riscv64.slaspec` (full RV64IMC) and `x86-64.slaspec`
  (common integer + SSE subset) — byte-exact vs objdump where covered

## ✅ v0.4 — Decompiler (Ghidra rotor)
- CFG + iterative dominators
- Expression reconstruction, registers as single C variables
- Stack-frame locals, call emission (auipc+jalr resolution), if/return
  structuring, goto/labels
- **Round-trip verified**: decompiled output recompiles and matches the
  original C (fib recursion, sum_array loop, compute/max3/absdiff)

## 🎯 v0.5 — Decompiler depth
- Loop structuring (while/do-while via dominators)
- Calling conventions (SystemV/Win64), return-value tracking
- Type propagation to kill cast noise; stack-slot typing
- x86 flags model (EFLAGS as p-code) so jcc semantics decompile properly
- x86 spec coverage growth (VEX/AVX, x87, rare forms)

## 🎯 v0.6 — GUI + scripting
- Dear ImGui listing/navigation, function map, xrefs
- Project model; scripting API (Lua) driving the core library

## 🎯 v0.7 — Symbolic execution (angr rotor) ⭐ the merge
The p-code interpreter already models values as {const, unknown}; generalize
it to **symbolic values** (expression trees over registers/memory):
1. `SymValue` = const | symbolic-expr; evaluator handles INT_*/LOAD/STORE/
   BRANCH symbolically (the current `Value = optional<uint64>` becomes a
   symbolic tree with the same op semantics — verified by the round-trip)
2. **Concolic first**: run with concrete inputs, collect path conditions
   (CBRANCH on symbolic values), flip branches to explore new paths
3. **Solver**: minimal internal bit-vector solver for common conditions
   (equality/inequality/range); optional Z3 linkage behind an interface
   (keeps zero-dep default)
4. `centrifuge explore <file> --from <addr> --to <addr>` — path finding;
   `--trace` for input synthesis (angr's "what input reaches X?" use case)
5. State merging (equivalence-class dedup), loop bounding, worklist policies

## 🎯 v0.8 — Breadth
- More formats: Mach-O, raw, archives; more ISAs via specs (ARM, MIPS, ...)
- Taint tracking on p-code; angrop-style exploit primitive search
- Structured CFG recovery from symbolic exploration (angr's CFGEmulated)

## Non-goals (for now)
- Binary patching/export, diffing, debugger integration

## Guiding principle
Every layer is validated against deterministic hand-built binaries
(`tools/make_samples.cpp`) and independent tools (GNU objdump, host gcc for
round-trips). The p-code semantics are proven by the decompiler round-trip —
the same semantics power the symbolic engine, so the two rotors can never
disagree.
