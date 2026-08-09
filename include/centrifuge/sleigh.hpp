// centrifuge - a Ghidra reimplementation in C++17
// sleigh.hpp - SLEIGH-lite: spec-driven disassembly engine (Ghidra's Sleigh
// reimplemented for a practical subset of the .slaspec language)
//
// Supported spec subset:
//   define space ram size=8 type=ram_space default;
//   define space regs size=8 type=register_space;
//   define register offset=0 size=8 [ x0 x1 ... ];
//   token t32 (4) { field = (msb:lsb); composed = (msb:lsb)@shift, ...; };
//   attach variables [ field ] [ reg names ];
//   :name [op1, op2] is pattern & pattern { pcode stmts } ;
// Patterns: field=value, field, field:operand  ("&" separated)
// P-code stmts: lhs = expr; goto expr; if (expr) goto expr; call expr;
//               return; *[:N] (expr) = expr;
// Expressions: ints, operands, regs, inst_next/inst_start, + - * / % << >>
//              s>> s/ s% & | ^ ~ ! == != < <= > >= s< s<= s> s>=
//              sext(v[,N]) zext(v[,N]) load(addr[,N])
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "centrifuge/pcode.hpp"

namespace centrifuge {

// ---- spec model ----

struct SpecField {
    struct Piece {
        int msb = 0, lsb = 0, shift = 0;
    };
    std::string name;
    std::vector<Piece> pieces; // value = sum((raw>>lsb & mask) << shift)
    int bits = 0;
    int size = 0; // bytes (ceil(bits/8))
    bool attached = false;
    std::vector<std::string> regs; // attach variables list
    int token = 0;                 // owning token index
};

struct SpecToken {
    std::string name;
    int size = 4; // bytes
};

struct SpecRegister {
    std::string name;
    uint64_t offset = 0;
    int size = 8;
};

struct SpecCtor {
    std::string name;
    std::vector<std::string> operands; // operand names in order

    struct Term {
        enum Kind { FIELD_EQ, FIELD_EXPORT } kind = FIELD_EXPORT;
        std::string field;   // token field name
        std::string operand; // exported operand name (FIELD_EXPORT)
        uint64_t value = 0;  // FIELD_EQ
    };
    std::vector<Term> terms;

    // parsed semantics (owned nodes)
    struct SExpr;
    struct SStmt;
    std::vector<SStmt> stmts;
};

struct SpecCtor::SExpr {
    enum Kind { VAR, CONST, INST_NEXT, INST_START, BINOP, UNOP, SEXT, ZEXT, LOAD } kind = CONST;
    std::string var;
    uint64_t cval = 0;
    int op = 0; // char code for BINOP/UNOP
    int bits = 0;
    std::unique_ptr<SExpr> a, b;
};

struct SpecCtor::SStmt {
    enum Kind { ASSIGN, GOTO, CGOTO, CALL, RET, STORE } kind = ASSIGN;
    std::string lhs; // ASSIGN
    std::unique_ptr<SExpr> lhsE, rhsE, condE; // STORE: lhsE=addr, rhsE=value
    int storeSize = 0;
};

// ---- engine ----

class SleighEngine {
public:
    // Parse a .slaspec source. Returns false and fills err on failure.
    bool loadSpec(const std::string& text, std::string& err);

    // Disassemble one instruction at addr. `read` must return true and fill
    // buf with n bytes of the instruction (n <= token size).
    bool disassemble(
        const std::function<bool(uint64_t addr, void* buf, size_t n)>& read,
        uint64_t addr, PcodeInsn& out, std::string& err) const;

    const std::vector<SpecCtor>& ctors() const { return ctors_; }
    std::string tokenName() const {
        return tokens_.empty() ? std::string() : tokens_[0].name;
    }
    int tokenSize() const { // max instruction size in bytes
        int m = 0;
        for (const auto& t : tokens_) m = std::max(m, t.size);
        return m;
    }

private:
    std::vector<SpecRegister> regs_;
    std::map<std::string, uint64_t> regOffsets_;
    std::vector<SpecToken> tokens_;
    std::vector<SpecField> fields_; // flattened; SpecField::token indexes tokens_
    std::map<std::string, int> fieldIdx_;
    std::vector<SpecCtor> ctors_;
    bool archX86_ = false; // x86-style: prefix scan + ModRM magic terms
    mutable int x86Opsz_ = 0; // current operand size during disassembly

    // per-instruction emission state
    mutable uint64_t nextId_ = 1;
    mutable std::map<uint64_t, Varnode> cache_; // register varnodes

    const SpecField* findField(const std::string& name) const;
    const SpecRegister* findReg(const std::string& name) const;

    Varnode* makeVarnode(PcodeInsn& pi, Varnode::Kind k, uint64_t offset,
                         int size, const std::string& name = "") const;
    uint64_t regVarnode(PcodeInsn& pi, const SpecRegister& r) const;
    uint64_t constVarnode(PcodeInsn& pi, uint64_t v, int size) const;
    uint64_t evalExpr(PcodeInsn& pi, const SpecCtor::SExpr& e) const;
};

// Disassembler adapter: lets the analysis passes / CLI use a spec engine
// through the standard Disassembler interface.
class SpecDisassembler : public Disassembler {
public:
    explicit SpecDisassembler(std::shared_ptr<const SleighEngine> eng)
        : eng_(std::move(eng)) {}
    bool disasmOne(const MemoryImage& mem, uint64_t addr, Insn& out) override;
    std::string backendName() const override;

private:
    std::shared_ptr<const SleighEngine> eng_;
};

} // namespace centrifuge
