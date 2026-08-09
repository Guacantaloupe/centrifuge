# Roadmap — reimplementing Ghidra in C++17, 100% dependency-free

Ghidra's architecture maps cleanly onto layers. Each milestone is
independently testable. No external disassembler/decoder libraries — every
byte-level decoder is written from scratch (this is what makes the project
"100% C++" in the same spirit as Ghidra's own Sleigh).

## ✅ v0.1 — Foundation (done)
- Memory image model with per-block permissions
- ELF32/ELF64 loader (PT_LOAD image, sections, symtab/dynsym, entry)
- PE32/PE32+ loader (sections, export table)
- Disassembler abstraction with branch-target resolution
- Function discovery: symbol seeds + recursive-descent scan
- CLI: `info`, `funcs`, `disasm`, `dump`

## ✅ v0.2 — 100% C++ decoders (done)
- Removed the Capstone dependency entirely
- Hand-written x86/x86-64 decoder: prefixes (REX/66/67/F2/F3/segments),
  ModRM/SIB/disp/imm, all common integer instructions, Jcc/CMOVcc/SETcc,
  SSE movs/arith (MOVUPS/SS/SD, MOVAPS, MOVDQA/DQU, MOVD/Q, XORPS/PD, PXOR),
  system instructions, group tables, exact lengths
- Hand-written RISC-V decoder: RV32I/RV64I + M extension + compressed (C)
  extension — matches objdump on real compiler output
- C++ test-sample generator (`tools/make_samples.cpp`) replaces the Python one
- Validated vs GNU objdump on notepad.exe + kernel32.dll: 0 errors
- Roadmap items promoted: **string discovery, CFG-based function discovery,
  xrefs, call graph** (next)

## 🎯 v0.3 — The Sleigh gap: spec-driven disassembly
Ghidra's disassembler is driven by `.sla` language specs. This is the
defining milestone — it replaces the hand-written tables with a general
engine:
1. A **p-code engine**: varnodes, micro-ops (COPY, INT_ADD, BRANCH, CALL,
   LOAD/STORE, ...), a tiny interpreter + validator
2. A **SLEIGH parser** for a practical subset of `.slaspec` (constructor
   tables, operand fields, pattern matching, semantic sections emitting p-code)
3. Port the x86/RISC-V decoders onto Sleigh specs (new ISAs then come from
   spec files, not C++ tables)
4. `ghra <file> pcode <addr>` — dump p-code listings

## 🎯 v0.4 — Decompiler front end
- P-code → CFG (basic blocks, dominators)
- SSA construction, dead-code elimination, constant propagation, copy
  propagation, expression tree building
- `ghra <file> decompile <fn>` — first C-like output

## 🎯 v0.5 — Decompiler back end + types
- Calling conventions (cdecl/SystemV/Win64), stack-frame recovery,
  param/return typing, structure recovery
- High-quality C emitter (loops, switches, if-chains)
- Goal: decompile the v0.1 samples to *exactly* the C they were written from

## 🎯 v0.6 — GUI + scripting
- Dear ImGui (or Qt) listing window: navigation, function map, cross-refs
- Project model (multi-file workspace)
- Scripting API (Lua via sol2, or embedded Python) driving the core library

## 🎯 v0.7 — Breadth
- More formats: Mach-O, raw, archives
- More ISAs: ARM/AArch64, MIPS, PPC, 68K, AVR (spec files once v0.3 lands)
- x86 VEX/EVEX (AVX/AVX2/AVX-512) coverage, x87
- Analysis: calling-convention recovery, switch-table recovery, type
  propagation, obfuscation-resistant passes

## Non-goals (for now)
- Binary patch/export round-trip, diffing, debugger integration

## Guiding principle
Each layer is validated against deterministic hand-built binaries
(`tools/make_samples.cpp`) *and* against independent decoders (GNU objdump),
so a regression in any decoder or loader is always reproducible.
