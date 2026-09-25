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

## ✅ Native Source Recovery Backend (Decompiler roadmap, Phase 1-3)
Machine Semantic Backend (Binary → p-code → machine-like C++ → compile →
verifier) remains the correctness oracle.  The new Native Source Recovery
Backend lifts provably-stable machine state into real source semantics:

- **StackFrameAnalysis** (src/stack_recovery.cpp): prologue/epilogue
  recovery on the p-code CFG — frame size, frame pointer, saved registers,
  sp-bias tracking through x86 unique-carrier p-code (sp = sp - 8 is
  materialised as u = sp - 8; *(u) = ...; sp = u)
- **StackSlotRecovery**: stable stack accesses (rbp/rsp + const) become
  StackSlot IR objects with width, read/write sites, lifetime, role
  (LOCAL / SAVED_REGISTER / PARAMETER / RETURN_ADDRESS)
- **VariablePromotion**: safe LOCAL slots (single width, no overlap, no
  address escape) promote to typed locals (uint32_t local_m28); anything
  unprovable falls back to the Machine Semantic representation
- Overlap detection, address-taken (lea / escaped-address) detection,
  mixed-width fallback
- CLI: decompile-native <addr> emits the native view
- Golden tests: 	est_stack_recovery (frame-pointer, rsp-relative,
  parameter/return-address, mixed-width, address-taken functions)

Next phases: CallingConventionRecovery → FunctionPrototypeRecovery →
TypeRecovery → MemoryObjectRecovery → ControlFlowStructuring.

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

**Delivered (WS6)**: the rotor is real and now *feeds the decompiler*.
- `reach <addr>` derives a verified concrete input that reaches a target
  (stdin/argv/strcmp models, interval solver + concrete replay proof).
- `explore-indirect` runs bounded BFS exploration to completion and records
  every indirect call/jump site whose target concretized, with the full
  observed target set per site.
- `decompile-native --sym-explore` pipes those sites into the decompiler:
  single-target indirect calls/tail-jumps devirtualize into direct named
  calls (e.g. a function pointer loaded from a global becomes
  `return add(arg0, arg1, ...)`); multi-target sites stay generic
  dispatchers (switch-shaped evidence, not yet structured).
- Enablers: `jmp/call r/m64` pcode is a real LOAD+BRANCHIND/CALLIND (was a
  bogus direct branch to the operand address); PE IAT slots are bound to
  synthetic `ret` stubs so import crossings resolve to named targets.
- Windows kernel/driver recovery: PE subsystem/characteristics extracted,
  native-subsystem entry named `DriverEntry`, ~50 ntoskrnl/hal import
  prototypes (IoCreateDevice, ExAllocatePool2, Rtl*, Ke*, Mm*, HAL port I/O).

- Decompiler analysis engine (WS7): the exploration run now also records
  branch-direction coverage (per-branch bitmask of executed successors) and
  the set of visited pcs.  `decompile-native --sym-explore` uses it for
  unreachable-branch elimination: a conditional observed in only one
  direction emits that direction directly with a `/* symbolic: branch
  always ... */` annotation and the dead arm disappears; blocks no explored
  state reached are annotated too.  Gated on a complete run (budget
  exhaustion disables elimination, since unobserved then means "unknown",
  not "dead").

Still open: state merging (item 5), switch structuring from multi-target
jump sites, CMOV/select concretization in the executor (limits coverage of
register-indirect dispatches selected by cmov).

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

## Phase 10: RegisterPromotion + ABI Binding (Final Leap: simulation -> source)

**Goal (user acceptance criteria)**: for successfully recovered plain functions the
generated C/C++ compiles with a normal compiler producing natural Windows x64 ABI:
no simulated RSP, no manual register argument passing, no redundant
recovered_load/store, no fixed PE addresses, no Guest Stack, no NativeCallBridge
for plain function calls, Windows API called via real prototypes.

**Current gap (evidence, Blender 0x140001030)**: output is register-level semantics:
- simulated RSP: sp = rsp - 8\, stack slots as \*(uint64_t*)(rsp+K)- manual args: cx = 5368714496; rdx = rsp+48; rax = FUN_14000ca60(rdi,rsi,rdx,rcx,r8,r9,...)  (sleigh CALLIND fixed register order, not caller-semantic order)
- flag simulation: r4096..r4101 = CF/PF/AF/ZF/SF/OF + __builtin_parity noise
- fixed PE addresses: g_data_146589b00, 0x140001000 constants
- stack slots as raw pointer load/store (17 slots, 1 promoted)

**Sub-phases**:
- 10a Entry-parameter ABI-ization: entry defs of rcx/rdx/r8/r9/xmm0-3 that are
  used before redefinition become declared params (param1..N, width/sign from
  use evidence); entry spills like \local_m76 = (uint32_t)(rcx)\ fold into params.
- 10b Call-site ABI-ization: collect (abi-slot -> last-written value) before each
  call, emit F(arg1=rcx, arg2=rdx, arg3=r8, arg4=r9, stack...) in real ABI order;
  internal callee signatures come from 10a (bidirectional binding).
- 10c Return-value promotion: function-exit rax/xmm0 results bound to calls.
- 10d Param/return type refinement (width/sign/float via TypeRecovery evidence).
- 10e General register promotion: rbx/rsi/rdi/r12-r15 live ranges -> locals (SSA).
- 10f Simulated-RSP elimination: fixed inc/dec + slot accesses -> compiler frame.
- 10g Dead-flag elimination: r4096..r4101 inactive at branch points.
- 10h Address symbolization: constant addresses -> symbol refs.

**Verification**: native view output for Blender funcs must compile with g++ and
contain zero simulated-rsp ops, zero r409x, zero fixed PE addrs; unit tests per
sub-phase; ctest 13/13 + Blender benchmark stay green. Oracle (machine-semantic
recovered project) remains untouched.

**Progress**:
- 10a done (`c49756c`): entry ABI registers read before redefinition are named
  param1..N (win64 rcx/rdx/r8/r9) with a `// params:` header comment, gated on
  `!useRecoveredRuntime` so the oracle project stays byte-identical.
- 10b-1 done (`0ef227a`): internal call sites emit Windows x64 argument order
  (rcx, rdx, r8, r9, stack...) via per-callee lazy signature recovery (FunctionIR
  + memo cache; full ProgramAnalysis.build is too slow for interactive use).
- 10b-2 done (`fc35152`): pre-call argument setup inlined into call sites
  (rcx = K; rdx = rsp+48; FUN(rcx,rdx,...) -> FUN(K, rsp+48, ...)) via a
  block-local register->expression map with dependency invalidation.
- 10c done (`7b4c282`): return-register setup inlined into `return` statements;
  `x^x`/`x-x` folds to 0 (`be3c96e`, 10e start).
- 10g done (`b0cb764`): function-level live-flag pre-analysis drops dead
  r4096..r4101 writes (425 -> 328 lines on 0x140001030).
- 10h done (HEAD): address symbolization enhancements.  (1) GlobalObjectRecovery
  gains objectContaining(), so accesses inside a recovered object's span
  (`g_data_1468ce6e0 + 1`) keep the symbol instead of falling back to a raw
  absolute-address cast.  (2) Call-site arguments that are bare constants
  pointing at printable, NUL-terminated data-segment strings are emitted as
  string literals (`FUN_140385810("BLENDER_RESTORE_LD_PRELOAD", ...)`);
  code addresses and binary data stay numeric.
- 10d done: parameter width inference - entry-block references to
  ABI parameters narrower than 64 bits (e.g. `(uint32_t)(param1)`) annotate
  the `// params:` header comment (`param1=rcx (uint32_t)`), recording the
  usage evidence for downstream prototype binding; references after a
  redefinition are ignored.
- 10e done: dead register-write elimination.  A dual block-level
  liveness analysis (real operand reads vs ABI call-argument reads) plus
  instruction-level read positions drops side-effect-free writes that are
  never read again (e.g. `rcx = 5368714672;` before a call whose argument
  text inlines that constant).  Constant argument setups are always inlined
  by 10b-2, so call-argument registers only block elimination of
  non-constant definitions; the return register and everything reachable
  from successors stay conservative.  Gated on `!useRecoveredRuntime` so
  the oracle and riscv paths are byte-identical.
- 10f done: push/pop save slots are promoted to `saved_m<slot>` variables.
  A function-level pre-analysis tracks the simulated rsp bias block by block,
  confirms slots written exactly once by a push (rsp-8) and restored exactly
  once by a pop (rsp+8) into the same register, and the emitter folds the paired
  rsp writes away.  Later rsp-relative flag expressions and the frame allocation
  are re-based via a per-emitter rspRebase text rewrite so the C stays
  semantically identical (the `sub rsp,104` lands the output variable exactly on
  the simulated frame).  Prologue of 0x140001030: 16 lines -> 8 `saved_mX` lines;
  epilogue pops collapse to plain register restores.  Conservative fallback for
  slots with multiple readers/writers (e.g. mid-function frames).

- 10i done (indirect-jump trampoline recognition): a block ending in an
  unresolved indirect jump (BRANCHIND) whose target register was written in
  the same block (the data-slot jump-board pattern `mov reg,[rip+slot];
  jmp *reg`) is a tail call, not a fallthrough.  The terminator was
  previously dropped and the function decompiled to a void body with a dead
  load, losing the dispatch (Blender allocator/CRT thunks; thunk_fix.py
  patched the output afterwards).  Now emits
  `return recovered_dispatch(rax, rcx, rdx, r8, r9, 0, 0, 0, 0);` in
  recovered-runtime mode and `return ((uint64_t (*)(...))(uintptr_t)rax)
  (rcx, rdx, r8, r9);` in native view, forwarding the live ABI argument
  registers (native thunks forward the caller's registers untouched).
  A jump on an unknown incoming register (e.g. switch dispatch) stays
  untouched.  Verified on real Blender 5.2 jump boards (0x14041F200/210/
  230): recovered-runtime emits the dispatch, native view compiles clean
  with g++ -O2 -Wall.  Test: tests/test_trampoline.cpp.
