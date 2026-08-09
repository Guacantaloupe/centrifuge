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

## ✅ v0.3 — The Sleigh gap: spec-driven disassembly (done)
- **p-code engine** (`pcode.hpp/cpp`): varnodes, ~35 ops, `PcodeInsn` per
  instruction, interpreter (constant folding + concrete semantics)
- **SLEIGH-lite parser** (`sleigh.cpp`): spaces, registers, tokens with bit
  fields (incl. composed `(msb:lsb)@shift` fields), attach variables,
  constructors with first-match patterns; multi-token support (16-bit
  compressed + 32-bit base); emits p-code with incremental folding;
  classifies RET/CALL/JMP/JCC and resolves branch targets
- **`sleigh/riscv64.slaspec`**: full RV64IMC language module (~90
  constructors incl. compressed) — validated vs objdump on real compiler
  output, 0 mismatches
- `test_sleigh`: disassembly + interpreter semantics tests
- Fixed a real semantic bug found via decompilation: RISC-V branch/jump
  targets are PC-relative to the instruction itself, not the next
  instruction

## ✅ v0.4-lite — CFG + first C decompiler (done)
- **CFG** (`cfg.cpp`): basic blocks from p-code (fallthrough-first edges,
  block-start boundaries), iterative dominators, DOT output
- **Decompiler** (`decompile.cpp`): per-block p-code expression
  reconstruction (copy propagation through temps, constant folding, 32-bit
  SUBPIECE+INT_SEXT as `(int64_t)(int32_t)(uint32_t)(x)` casts), registers
  as single C variables (no SSA versioning needed — C sequential semantics
  match the machine, and joins come out correct), if/return structuring for
  single-pred return blocks, goto/labels elsewhere
- **Round-trip verified**: decompiled compute/max3/absdiff compile and
  produce identical results to the original C on 20 test vectors

## 🎯 v0.4 — Decompiler front end (remaining)
- SSA + phi nodes (needed for full register-liveness correctness)
- Stack-frame recovery (sp-relative locals) — unlocks non-leaf functions
- Call argument tracking (a0-a7 by convention) and CALL emission
- Loop structuring (while/for via dominators)
- Type propagation to clean up the cast noise

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
