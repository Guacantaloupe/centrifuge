// ghra - a Ghidra reimplementation in C++17
// sleigh.cpp - SLEIGH-lite: spec parsing, pattern matching, p-code emission
//
// Operator encoding for expression trees (unique int codes):
//   '+','-','*','/','%','&','|','^'  single chars
//   '<','>','==','!=','<=','>='       char pairs (hi<<8|lo)
//   's<','s>','s<=','s>=','s>>','s/','s%'  signed: 0x40000000 | code
//   '<<' 0x3C3C   '>>' 0x3E3E
#include "ghra/sleigh.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <set>
#include <sstream>

namespace ghra {

// ---------------------------------------------------------------------------
// lexer
namespace {

struct Tok {
    enum Kind { ID, INT, OP, END } kind = END;
    std::string text; // ID / OP text
    uint64_t ival = 0;
};

class Lexer {
public:
    explicit Lexer(const std::string& s) : s_(s) {}
    std::vector<Tok> all(std::string& err);

private:
    const std::string& s_;
    size_t p_ = 0;
    void skipWs();
    bool lexOne(Tok& t);
};

void Lexer::skipWs() {
    for (;;) {
        while (p_ < s_.size() &&
               std::isspace(static_cast<unsigned char>(s_[p_])))
            p_++;
        if (p_ + 1 < s_.size() && s_[p_] == '/' && s_[p_ + 1] == '/') {
            while (p_ < s_.size() && s_[p_] != '\n') p_++;
            continue;
        }
        if (p_ + 1 < s_.size() && s_[p_] == '/' && s_[p_ + 1] == '*') {
            p_ += 2;
            while (p_ + 1 < s_.size() && !(s_[p_] == '*' && s_[p_ + 1] == '/'))
                p_++;
            p_ += 2;
            continue;
        }
        break;
    }
}

bool Lexer::lexOne(Tok& t) {
    skipWs();
    if (p_ >= s_.size()) {
        t.kind = Tok::END;
        return true;
    }
    const char c = s_[p_];
    if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
        size_t q = p_;
        while (p_ < s_.size() &&
               (std::isalnum(static_cast<unsigned char>(s_[p_])) ||
                s_[p_] == '_' || s_[p_] == '.'))
            p_++;
        t.kind = Tok::ID;
        t.text = s_.substr(q, p_ - q);
        if (t.text == "s" && p_ < s_.size()) {
            const char n = s_[p_];
            if (n == '<' || n == '>' || n == '/' || n == '%') {
                t.kind = Tok::OP;
                t.text = std::string("s") + n;
                p_++;
                if ((n == '<' || n == '>') && p_ < s_.size() &&
                    s_[p_] == '=') {
                    t.text += "=";
                    p_++;
                } else if (n == '>' && p_ < s_.size() && s_[p_] == '>') {
                    t.text += ">";
                    p_++;
                }
            }
        }
        return true;
    }
    if (std::isdigit(static_cast<unsigned char>(c))) {
        uint64_t v = 0;
        if (c == '0' && p_ + 1 < s_.size() &&
            (s_[p_ + 1] == 'x' || s_[p_ + 1] == 'X')) {
            p_ += 2;
            while (p_ < s_.size() &&
                   std::isxdigit(static_cast<unsigned char>(s_[p_]))) {
                v = v * 16 +
                    (s_[p_] <= '9' ? s_[p_] - '0'
                                   : (s_[p_] | 0x20) - 'a' + 10);
                p_++;
            }
        } else {
            while (p_ < s_.size() &&
                   std::isdigit(static_cast<unsigned char>(s_[p_]))) {
                v = v * 10 + (s_[p_] - '0');
                p_++;
            }
        }
        t.kind = Tok::INT;
        t.ival = v;
        return true;
    }
    auto two = [&](char a, char b) {
        return p_ + 1 < s_.size() && s_[p_] == a && s_[p_ + 1] == b;
    };
    if (two('<', '<')) { t.kind = Tok::OP; t.text = "<<"; p_ += 2; return true; }
    if (two('>', '>')) { t.kind = Tok::OP; t.text = ">>"; p_ += 2; return true; }
    if (two('=', '=')) { t.kind = Tok::OP; t.text = "=="; p_ += 2; return true; }
    if (two('!', '=')) { t.kind = Tok::OP; t.text = "!="; p_ += 2; return true; }
    if (two('<', '=')) { t.kind = Tok::OP; t.text = "<="; p_ += 2; return true; }
    if (two('>', '=')) { t.kind = Tok::OP; t.text = ">="; p_ += 2; return true; }
    t.kind = Tok::OP;
    t.text = std::string(1, c);
    p_++;
    return true;
}

std::vector<Tok> Lexer::all(std::string& err) {
    std::vector<Tok> out;
    Tok t;
    for (;;) {
        lexOne(t);
        if (t.kind == Tok::END) break;
        out.push_back(t);
    }
    return out;
}

bool isOp(const Tok& t, const char* s) {
    return t.kind == Tok::OP && t.text == s;
}
bool isId(const Tok& t, const char* s) {
    return t.kind == Tok::ID && t.text == s;
}

// signed-op flag
constexpr int SIGNED_OP = 0x40000000;

// expression parser (precedence climbing)
struct Parser {
    const std::vector<Tok>& tk;
    size_t i = 0;
    std::string err;

    explicit Parser(const std::vector<Tok>& t) : tk(t) {}

    const Tok& peek() const { return tk[std::min(i, tk.size() - 1)]; }
    const Tok& next() { return tk[std::min(i++, tk.size() - 1)]; }
    bool eatOp(const char* s) {
        if (isOp(peek(), s)) {
            i++;
            return true;
        }
        return false;
    }
    bool eatId(const char* s) {
        if (isId(peek(), s)) {
            i++;
            return true;
        }
        return false;
    }

    using SExpr = SpecCtor::SExpr;

    std::unique_ptr<SExpr> parseExpr() { return parseCmp(); }

    std::unique_ptr<SExpr> parseCmp() {
        auto a = parseOr();
        for (;;) {
            int op = 0;
            if (isOp(peek(), "==")) op = '=' | ('=' << 8);
            else if (isOp(peek(), "!=")) op = '!' | ('=' << 8);
            else if (isOp(peek(), "<")) op = '<';
            else if (isOp(peek(), "<=")) op = '<' | ('=' << 8);
            else if (isOp(peek(), ">")) op = '>';
            else if (isOp(peek(), ">=")) op = '>' | ('=' << 8);
            else if (isOp(peek(), "s<")) op = SIGNED_OP | '<';
            else if (isOp(peek(), "s<=")) op = SIGNED_OP | ('<' | ('=' << 8));
            else if (isOp(peek(), "s>")) op = SIGNED_OP | '>';
            else if (isOp(peek(), "s>=")) op = SIGNED_OP | ('>' | ('=' << 8));
            if (!op) break;
            i++;
            auto b = parseOr();
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::BINOP;
            e->op = op;
            e->a = std::move(a);
            e->b = std::move(b);
            a = std::move(e);
        }
        return a;
    }
    std::unique_ptr<SExpr> parseOr() {
        auto a = parseXor();
        while (eatOp("|")) {
            auto b = parseXor();
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::BINOP;
            e->op = '|';
            e->a = std::move(a);
            e->b = std::move(b);
            a = std::move(e);
        }
        return a;
    }
    std::unique_ptr<SExpr> parseXor() {
        auto a = parseAnd();
        while (eatOp("^")) {
            auto b = parseAnd();
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::BINOP;
            e->op = '^';
            e->a = std::move(a);
            e->b = std::move(b);
            a = std::move(e);
        }
        return a;
    }
    std::unique_ptr<SExpr> parseAnd() {
        auto a = parseShift();
        while (eatOp("&")) {
            auto b = parseShift();
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::BINOP;
            e->op = '&';
            e->a = std::move(a);
            e->b = std::move(b);
            a = std::move(e);
        }
        return a;
    }
    std::unique_ptr<SExpr> parseShift() {
        auto a = parseAdd();
        for (;;) {
            int op = 0;
            if (isOp(peek(), "<<")) op = '<' | ('<' << 8);
            else if (isOp(peek(), ">>")) op = '>' | ('>' << 8);
            else if (isOp(peek(), "s>>")) op = SIGNED_OP | ('>' | ('>' << 8));
            if (!op) break;
            i++;
            auto b = parseAdd();
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::BINOP;
            e->op = op;
            e->a = std::move(a);
            e->b = std::move(b);
            a = std::move(e);
        }
        return a;
    }
    std::unique_ptr<SExpr> parseAdd() {
        auto a = parseMul();
        for (;;) {
            int op = 0;
            if (isOp(peek(), "+")) op = '+';
            else if (isOp(peek(), "-")) op = '-';
            if (!op) break;
            i++;
            auto b = parseMul();
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::BINOP;
            e->op = op;
            e->a = std::move(a);
            e->b = std::move(b);
            a = std::move(e);
        }
        return a;
    }
    std::unique_ptr<SExpr> parseMul() {
        auto a = parseUnary();
        for (;;) {
            int op = 0;
            if (isOp(peek(), "*")) op = '*';
            else if (isOp(peek(), "/")) op = '/';
            else if (isOp(peek(), "s/")) op = SIGNED_OP | '/';
            else if (isOp(peek(), "%")) op = '%';
            else if (isOp(peek(), "s%")) op = SIGNED_OP | '%';
            if (!op) break;
            i++;
            auto b = parseUnary();
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::BINOP;
            e->op = op;
            e->a = std::move(a);
            e->b = std::move(b);
            a = std::move(e);
        }
        return a;
    }
    std::unique_ptr<SExpr> parseUnary() {
        if (isOp(peek(), "-")) {
            i++;
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::UNOP;
            e->op = '-';
            e->a = parseUnary();
            return e;
        }
        if (isOp(peek(), "~")) {
            i++;
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::UNOP;
            e->op = '~';
            e->a = parseUnary();
            return e;
        }
        if (isOp(peek(), "!")) {
            i++;
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::UNOP;
            e->op = '!';
            e->a = parseUnary();
            return e;
        }
        if (isId(peek(), "sext") || isId(peek(), "zext")) {
            const bool isSext = isId(peek(), "sext");
            i++;
            if (!eatOp("(")) { err = "expected ( after sext/zext"; return {}; }
            auto a = parseExpr();
            auto e = std::make_unique<SExpr>();
            e->kind = isSext ? SExpr::SEXT : SExpr::ZEXT;
            e->a = std::move(a);
            if (eatOp(",")) {
                if (peek().kind != Tok::INT) {
                    err = "expected int in sext/zext";
                    return {};
                }
                e->bits = static_cast<int>(next().ival);
            }
            if (!eatOp(")")) { err = "expected )"; return {}; }
            return e;
        }
        if (isId(peek(), "load")) {
            i++;
            if (!eatOp("(")) { err = "expected ( after load"; return {}; }
            auto a = parseExpr();
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::LOAD;
            e->a = std::move(a);
            if (eatOp(",")) {
                if (peek().kind != Tok::INT) { err = "expected int in load"; return {}; }
                e->bits = static_cast<int>(next().ival);
            }
            if (!eatOp(")")) { err = "expected )"; return {}; }
            return e;
        }
        return parsePrimary();
    }
    std::unique_ptr<SExpr> parsePrimary() {
        auto e = std::make_unique<SExpr>();
        if (peek().kind == Tok::INT) {
            e->kind = SExpr::CONST;
            e->cval = next().ival;
            return e;
        }
        if (isId(peek(), "inst_next")) {
            i++;
            e->kind = SExpr::INST_NEXT;
            return e;
        }
        if (isId(peek(), "inst_start")) {
            i++;
            e->kind = SExpr::INST_START;
            return e;
        }
        if (peek().kind == Tok::ID) {
            e->kind = SExpr::VAR;
            e->var = next().text;
            return e;
        }
        if (eatOp("(")) {
            auto inner = parseExpr();
            if (!eatOp(")")) { err = "expected )"; return {}; }
            return inner;
        }
        err = "unexpected token in expression: " + peek().text;
        return {};
    }
};

} // namespace

// ---------------------------------------------------------------------------
// spec loading

static bool parseFieldSpec(const std::string& text, SpecField& f) {
    size_t p = 0;
    int maxBit = 0;
    auto skip = [&]() {
        while (p < text.size() &&
               std::isspace(static_cast<unsigned char>(text[p])))
            p++;
    };
    skip();
    if (p >= text.size() || text[p] != '(') return false;
    p++;
    for (;;) {
        skip();
        auto readInt = [&](int& v) {
            skip();
            int r = 0;
            if (p >= text.size() ||
                !std::isdigit(static_cast<unsigned char>(text[p])))
                return false;
            while (p < text.size() &&
                   std::isdigit(static_cast<unsigned char>(text[p]))) {
                r = r * 10 + (text[p] - '0');
                p++;
            }
            v = r;
            return true;
        };
        SpecField::Piece pc;
        int msb = 0, lsb = 0, shift = 0;
        if (!readInt(msb)) return false;
        skip();
        if (p < text.size() && text[p] == ':') {
            p++;
            if (!readInt(lsb)) return false;
        } else {
            lsb = msb;
        }
        skip();
        if (p < text.size() && text[p] == '@') {
            p++;
            if (!readInt(shift)) return false;
        } else {
            shift = 0; // plain fields are right-justified
        }
        pc.msb = msb;
        pc.lsb = lsb;
        pc.shift = shift;
        f.pieces.push_back(pc);
        maxBit = std::max(maxBit, shift + (msb - lsb + 1));
        skip();
        if (p < text.size() && text[p] == ',') {
            p++;
            continue;
        }
        break;
    }
    skip();
    if (p >= text.size() || text[p] != ')') return false;
    f.bits = maxBit;
    f.size = (f.bits + 7) / 8;
    return true;
}

bool SleighEngine::loadSpec(const std::string& text, std::string& err) {
    Lexer lx(text);
    auto tk = lx.all(err);
#ifdef GHRA_DEBUG_TOKENS
    for (const auto& t : tk) {
        if (t.kind == Tok::INT)
            std::fprintf(stderr, "[#%llu]",
                         static_cast<unsigned long long>(t.ival));
        else
            std::fprintf(stderr, "[%s]", t.text.c_str());
    }
    std::fprintf(stderr, "\n");
#endif

    auto fieldByName = [&](const std::string& n) -> SpecField* {
        for (auto& f : fields_)
            if (f.name == n) return &f;
        return nullptr;
    };

    for (size_t i = 0; i < tk.size();) {
        if (isId(tk[i], "define")) {
            i++;
            if (isId(tk[i], "arch")) {
                i++;
                if (tk[i].kind != Tok::ID) { err = "arch: bad name"; return false; }
                archX86_ = (tk[i].text == "x86");
                i++;
                if (!isOp(tk[i], ";")) { err = "arch: expected ;"; return false; }
                i++;
            } else if (isId(tk[i], "space")) {
                i++;
                if (tk[i].kind != Tok::ID) { err = "bad space name"; return false; }
                i++;
                if (!isId(tk[i], "size")) { err = "space: expected size="; return false; }
                if (!isOp(tk[i + 1], "=")) { err = "space: expected ="; return false; }
                i += 2;
                if (tk[i].kind != Tok::INT) { err = "space: bad size"; return false; }
                i++;
                if (!isId(tk[i], "type")) { err = "space: expected type="; return false; }
                i += 2;
                if (tk[i].kind != Tok::ID) { err = "space: bad type"; return false; }
                i++;
                if (isId(tk[i], "default")) i++;
                if (!isOp(tk[i], ";")) { err = "space: expected ;"; return false; }
                i++;
            } else if (isId(tk[i], "register")) {
                i++;
                if (!isId(tk[i], "offset")) { err = "register: expected offset="; return false; }
                i += 2;
                if (tk[i].kind != Tok::INT) { err = "register: bad offset"; return false; }
                uint64_t off = tk[i].ival;
                i++;
                if (!isId(tk[i], "size")) { err = "register: expected size="; return false; }
                i += 2;
                if (tk[i].kind != Tok::INT) { err = "register: bad size"; return false; }
                int sz = static_cast<int>(tk[i].ival);
                i++;
                if (!isOp(tk[i], "[")) { err = "register: expected ["; return false; }
                i++;
                uint64_t o = off;
                while (!isOp(tk[i], "]")) {
                    if (tk[i].kind != Tok::ID) { err = "register: bad name"; return false; }
                    SpecRegister r;
                    r.name = tk[i].text;
                    r.offset = o;
                    r.size = sz;
                    regs_.push_back(r);
                    regOffsets_[r.name] = o;
                    o += sz;
                    i++;
                }
                i++; // ]
                if (!isOp(tk[i], ";")) { err = "register: expected ;"; return false; }
                i++;
            } else {
                err = "unknown define: " + tk[i].text;
                return false;
            }
        } else if (isId(tk[i], "token")) {
            i++;
            if (tk[i].kind != Tok::ID) { err = "token: bad name"; return false; }
            SpecToken st;
            st.name = tk[i].text;
            i++;
            if (!isOp(tk[i], "(")) { err = "token: expected ("; return false; }
            i++;
            if (tk[i].kind != Tok::INT) { err = "token: bad size"; return false; }
            st.size = static_cast<int>(tk[i].ival);
            i++;
            if (!isOp(tk[i], ")")) { err = "token: expected )"; return false; }
            i++;
            if (!isOp(tk[i], "{")) { err = "token: expected {"; return false; }
            i++;
            const int tokIdx = static_cast<int>(tokens_.size());
            while (!isOp(tk[i], "}")) {
                if (tk[i].kind != Tok::ID) { err = "token: bad field name"; return false; }
                SpecField f;
                f.name = tk[i].text;
                i++;
                if (!isOp(tk[i], "=")) { err = "token: expected ="; return false; }
                i++;
                if (!isOp(tk[i], "(")) { err = "token: expected ("; return false; }
                i++; // skip (
                std::string spec = "(";
                while (!isOp(tk[i], ";")) { // gather until ';'
                    const Tok& t = tk[i];
                    if (t.kind == Tok::INT)
                        spec += std::to_string(t.ival);
                    else if (t.text != "(" && t.text != ")")
                        spec += t.text; // pieces carry no parens
                    i++;
                }
                spec += ")";
                if (!parseFieldSpec(spec, f)) {
                    err = "token: bad field spec for " + f.name;
                    return false;
                }
                i++; // ;
                f.token = tokIdx;
                fields_.push_back(f);
                fieldIdx_[f.name] = static_cast<int>(fields_.size()) - 1;
            }
            i++; // }
            tokens_.push_back(st);
        } else if (isId(tk[i], "attach")) {
            i++;
            if (!isId(tk[i], "variables")) { err = "attach: expected variables"; return false; }
            i++;
            if (!isOp(tk[i], "[")) { err = "attach: expected ["; return false; }
            i++;
            if (tk[i].kind != Tok::ID) { err = "attach: bad field name"; return false; }
            std::string fname = tk[i].text;
            i++;
            if (!isOp(tk[i], "]")) { err = "attach: expected ]"; return false; }
            i++;
            if (!isOp(tk[i], "[")) { err = "attach: expected [ regs"; return false; }
            i++;
            SpecField* f = fieldByName(fname);
            if (!f) { err = "attach: unknown field " + fname; return false; }
            f->attached = true;
            f->regs.clear();
            while (!isOp(tk[i], "]")) {
                if (tk[i].kind != Tok::ID) { err = "attach: bad register name"; return false; }
                f->regs.push_back(tk[i].text);
                i++;
            }
            i++; // ]
            if (!isOp(tk[i], ";")) { err = "attach: expected ;"; return false; }
            i++;
        } else if (isOp(tk[i], ":")) {
            i++;
            if (tk[i].kind != Tok::ID) { err = "ctor: bad name"; return false; }
            SpecCtor c;
            c.name = tk[i].text;
            i++;
            // operand list: :name op1, op2 is ... (Sleigh form, no brackets)
            while (tk[i].kind == Tok::ID && !isId(tk[i], "is")) {
                c.operands.push_back(tk[i].text);
                i++;
                if (isOp(tk[i], ",")) i++;
            }
            if (!isId(tk[i], "is")) {
                err = "ctor " + c.name + ": expected is, got " + tk[i].text;
                return false;
            }
            i++;
            bool first = true;
            while (!isOp(tk[i], "{")) {
                if (isOp(tk[i], "(") || isOp(tk[i], ")")) {
                    i++;
                    continue;
                }
                if (first) {
                    first = false;
                } else if (isOp(tk[i], "&")) {
                    i++;
                    continue;
                }
                if (tk[i].kind != Tok::ID) { err = "ctor: bad pattern term"; return false; }
                SpecCtor::Term t;
                t.field = tk[i].text;
                t.operand = tk[i].text;
                i++;
                if (isOp(tk[i], "=")) {
                    i++;
                    if (tk[i].kind != Tok::INT) { err = "ctor: bad pattern value"; return false; }
                    t.kind = SpecCtor::Term::FIELD_EQ;
                    t.value = tk[i].ival;
                    i++;
                } else if (isOp(tk[i], ":")) {
                    i++;
                    if (tk[i].kind != Tok::ID) { err = "ctor: bad export name"; return false; }
                    t.operand = tk[i].text;
                    i++;
                }
                c.terms.push_back(t);
            }
            i++; // {
            Parser ps(tk);
            ps.i = i;
            while (!isOp(tk[ps.i], "}")) {
                SpecCtor::SStmt st;
                if (isId(tk[ps.i], "goto")) {
                    ps.i++;
                    st.kind = SpecCtor::SStmt::GOTO;
                    st.rhsE = ps.parseExpr();
                    if (ps.err.empty() && !isOp(tk[ps.i], ";"))
                        ps.err = "goto: expected ;";
                    else if (ps.err.empty())
                        ps.i++;
                } else if (isId(tk[ps.i], "if")) {
                    ps.i++;
                    if (!isOp(tk[ps.i], "(")) { ps.err = "if: expected ("; break; }
                    ps.i++;
                    st.kind = SpecCtor::SStmt::CGOTO;
                    st.condE = ps.parseExpr();
                    if (!isOp(tk[ps.i], ")")) { ps.err = "if: expected )"; break; }
                    ps.i++;
                    if (!isId(tk[ps.i], "goto")) { ps.err = "if: expected goto"; break; }
                    ps.i++;
                    st.rhsE = ps.parseExpr();
                    if (!isOp(tk[ps.i], ";")) { ps.err = "if: expected ;"; break; }
                    ps.i++;
                } else if (isId(tk[ps.i], "call")) {
                    ps.i++;
                    st.kind = SpecCtor::SStmt::CALL;
                    st.rhsE = ps.parseExpr();
                    if (ps.err.empty() && !isOp(tk[ps.i], ";"))
                        ps.err = "call: expected ;";
                    else if (ps.err.empty())
                        ps.i++;
                } else if (isId(tk[ps.i], "return")) {
                    ps.i++;
                    st.kind = SpecCtor::SStmt::RET;
                    if (!isOp(tk[ps.i], ";")) { ps.err = "return: expected ;"; break; }
                    ps.i++;
                } else if (isOp(tk[ps.i], "*")) {
                    ps.i++;
                    st.kind = SpecCtor::SStmt::STORE;
                    if (isOp(tk[ps.i], ":")) {
                        ps.i++;
                        if (tk[ps.i].kind != Tok::INT) { ps.err = "store: bad size"; break; }
                        st.storeSize = static_cast<int>(tk[ps.i].ival);
                        ps.i++;
                    }
                    if (!isOp(tk[ps.i], "(")) { ps.err = "store: expected ("; break; }
                    ps.i++;
                    st.lhsE = ps.parseExpr();
                    if (!isOp(tk[ps.i], ")")) { ps.err = "store: expected )"; break; }
                    ps.i++;
                    if (!isOp(tk[ps.i], "=")) { ps.err = "store: expected ="; break; }
                    ps.i++;
                    st.rhsE = ps.parseExpr();
                    if (!isOp(tk[ps.i], ";")) { ps.err = "store: expected ;"; break; }
                    ps.i++;
                } else if (tk[ps.i].kind == Tok::ID &&
                           isOp(tk[ps.i + 1], "=")) {
                    st.kind = SpecCtor::SStmt::ASSIGN;
                    st.lhs = tk[ps.i].text;
                    ps.i += 2;
                    st.rhsE = ps.parseExpr();
                    if (ps.err.empty() && !isOp(tk[ps.i], ";"))
                        ps.err = "assign: expected ;";
                    else if (ps.err.empty())
                        ps.i++;
                } else {
                    ps.err = "bad statement at: " + tk[ps.i].text;
                    break;
                }
                if (!ps.err.empty()) break;
                c.stmts.push_back(std::move(st));
            }
            if (!ps.err.empty()) {
                err = "ctor " + c.name + ": " + ps.err;
                return false;
            }
            i = ps.i + 1; // past }
            if (!isOp(tk[i], ";")) {
                std::string dbg;
                for (size_t k = (i > 8 ? i - 8 : 0); k <= i; ++k)
                    dbg += "[" + tk[k].text + "]";
                err = "ctor " + c.name +
                      ": expected ; after }, got " + tk[i].text + " ps.i=" +
                      std::to_string(ps.i) + " at " + dbg;
                return false;
            }
            i++;
            ctors_.push_back(std::move(c));
        } else {
            std::string dbg;
            for (size_t k = (i > 3 ? i - 3 : 0); k <= i; ++k)
                dbg += "[" + tk[k].text + "]";
            err = "unexpected token: " + tk[i].text + " at " + dbg;
            return false;
        }
    }
    if (ctors_.empty()) {
        err = "no constructors in spec";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// helpers

const SpecField* SleighEngine::findField(const std::string& name) const {
    auto it = fieldIdx_.find(name);
    if (it == fieldIdx_.end()) return nullptr;
    return &fields_[it->second];
}

const SpecRegister* SleighEngine::findReg(const std::string& name) const {
    auto it = regOffsets_.find(name);
    if (it == regOffsets_.end()) return nullptr;
    for (const auto& r : regs_)
        if (r.offset == it->second && r.name == name) return &r;
    return nullptr;
}

Varnode* SleighEngine::makeVarnode(PcodeInsn& pi, Varnode::Kind k,
                                   uint64_t offset, int size,
                                   const std::string& name) const {
    Varnode v;
    v.id = nextId_++;
    v.kind = k;
    v.offset = offset;
    v.size = size;
    v.name = name;
    auto [it, ok] = pi.varnodes.emplace(v.id, v);
    return &it->second;
}

uint64_t SleighEngine::regVarnode(PcodeInsn& pi, const SpecRegister& r) const {
    const uint64_t key = (r.offset << 8) | (r.size & 0xFF);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        pi.varnodes[it->second.id] = it->second;
        return it->second.id;
    }
    Varnode* v = makeVarnode(pi, Varnode::REGISTER, r.offset, r.size, r.name);
    cache_[key] = *v;
    return v->id;
}

uint64_t SleighEngine::constVarnode(PcodeInsn& pi, uint64_t v, int size) const {
    Varnode* n = makeVarnode(pi, Varnode::CONST, v, size);
    return n->id;
}

namespace {

// constant-fold a binary op (both inputs known)
std::optional<uint64_t> foldBin(uint64_t a, uint64_t b, int op) {
    switch (op) {
    case '+': return a + b;
    case '-': return a - b;
    case '*': return a * b;
    case '/': return b == 0 ? std::nullopt : std::optional<uint64_t>(a / b);
    case '%': return b == 0 ? std::nullopt : std::optional<uint64_t>(a % b);
    case '&': return a & b;
    case '|': return a | b;
    case '^': return a ^ b;
    case '<': return a < b ? 1ULL : 0ULL;
    case '>': return a > b ? 1ULL : 0ULL;
    case '<' | ('=' << 8): return a <= b ? 1ULL : 0ULL;
    case '>' | ('=' << 8): return a >= b ? 1ULL : 0ULL;
    case '=' | ('=' << 8): return a == b ? 1ULL : 0ULL;
    case '!' | ('=' << 8): return a != b ? 1ULL : 0ULL;
    case SIGNED_OP | '<':
        return static_cast<int64_t>(a) < static_cast<int64_t>(b) ? 1ULL : 0ULL;
    case SIGNED_OP | '>':
        return static_cast<int64_t>(a) > static_cast<int64_t>(b) ? 1ULL : 0ULL;
    case SIGNED_OP | ('<' | ('=' << 8)):
        return static_cast<int64_t>(a) <= static_cast<int64_t>(b) ? 1ULL : 0ULL;
    case SIGNED_OP | ('>' | ('=' << 8)):
        return static_cast<int64_t>(a) >= static_cast<int64_t>(b) ? 1ULL : 0ULL;
    case '<' | ('<' << 8): return b < 64 ? (a << b) : 0ULL;
    case '>' | ('>' << 8): return b < 64 ? (a >> b) : 0ULL;
    case SIGNED_OP | ('>' | ('>' << 8)):
        return b < 64
                   ? static_cast<uint64_t>(static_cast<int64_t>(a) >> b)
                   : 0ULL;
    case SIGNED_OP | '/':
        return b == 0
                   ? std::nullopt
                   : std::optional<uint64_t>(static_cast<uint64_t>(
                         static_cast<int64_t>(a) / static_cast<int64_t>(b)));
    case SIGNED_OP | '%':
        return b == 0
                   ? std::nullopt
                   : std::optional<uint64_t>(static_cast<uint64_t>(
                         static_cast<int64_t>(a) % static_cast<int64_t>(b)));
    }
    return std::nullopt;
}

// map expression opcode to p-code op; sets swapped for '>' / '>=' forms
POp binPop(int op, bool& swapped) {
    swapped = false;
    switch (op) {
    case '+': return POp::INT_ADD;
    case '-': return POp::INT_SUB;
    case '*': return POp::INT_MULT;
    case '/': return POp::INT_DIV;
    case '%': return POp::INT_REM;
    case '&': return POp::INT_AND;
    case '|': return POp::INT_OR;
    case '^': return POp::INT_XOR;
    case '<' | ('<' << 8): return POp::INT_LEFT;
    case '>' | ('>' << 8): return POp::INT_RIGHT;
    case SIGNED_OP | ('>' | ('>' << 8)): return POp::INT_SRIGHT;
    case SIGNED_OP | '/': return POp::INT_SDIV;
    case SIGNED_OP | '%': return POp::INT_SREM;
    case '=' | ('=' << 8): return POp::INT_EQUAL;
    case '!' | ('=' << 8): return POp::INT_NOTEQUAL;
    case '<': return POp::INT_LESS;
    case '<' | ('=' << 8): return POp::INT_LESSEQUAL;
    case '>':
        swapped = true;
        return POp::INT_LESS;
    case '>' | ('=' << 8):
        swapped = true;
        return POp::INT_LESSEQUAL;
    case SIGNED_OP | '<': return POp::INT_SLESS;
    case SIGNED_OP | ('<' | ('=' << 8)): return POp::INT_SLESSEQUAL;
    case SIGNED_OP | '>':
        swapped = true;
        return POp::INT_SLESS;
    case SIGNED_OP | ('>' | ('=' << 8)):
        swapped = true;
        return POp::INT_SLESSEQUAL;
    }
    return POp::UNIMPLEMENTED;
}

} // namespace

// evaluate an expression into a varnode, emitting p-code; folds constants
uint64_t SleighEngine::evalExpr(PcodeInsn& pi, const SpecCtor::SExpr& e) const {
    auto opId = [&](const std::string& n) -> uint64_t {
        auto it = pi.named.find(n);
        return it == pi.named.end() ? 0 : it->second;
    };

    switch (e.kind) {
    case SpecCtor::SExpr::CONST: {
        Varnode* v = makeVarnode(pi, Varnode::CONST, e.cval, 8);
        return v->id;
    }
    case SpecCtor::SExpr::INST_NEXT: {
        Varnode* v = makeVarnode(pi, Varnode::CONST, pi.nextAddr, 8);
        return v->id;
    }
    case SpecCtor::SExpr::INST_START: {
        Varnode* v = makeVarnode(pi, Varnode::CONST, pi.addr, 8);
        return v->id;
    }
    case SpecCtor::SExpr::VAR: {
        if (e.var == "opsz" && x86Opsz_) {
            Varnode* v = makeVarnode(pi, Varnode::CONST,
                                     static_cast<uint64_t>(x86Opsz_), 8);
            return v->id;
        }
        if (uint64_t id = opId(e.var)) return id;
        if (const SpecRegister* r = findReg(e.var)) return regVarnode(pi, *r);
        return constVarnode(pi, 0, 8); // unknown var (shouldn't happen)
    }
    case SpecCtor::SExpr::BINOP: {
        const uint64_t a = evalExpr(pi, *e.a);
        const uint64_t b = evalExpr(pi, *e.b);
        const Varnode* va = pi.find(a);
        const Varnode* vb = pi.find(b);
        if (va && vb && va->isConst() && vb->isConst()) {
            if (auto f = foldBin(va->offset, vb->offset, e.op)) {
                Varnode* v = makeVarnode(pi, Varnode::CONST, *f, 8);
                return v->id;
            }
        }
        bool swapped = false;
        const POp pop = binPop(e.op, swapped);
        uint64_t ia = a, ib = b;
        if (swapped) std::swap(ia, ib);
        Varnode* out = makeVarnode(pi, Varnode::UNIQUE, nextId_++, 8);
        pi.ops.push_back(PcodeOp{pop, out->id, ia, ib, 0});
        return out->id;
    }
    case SpecCtor::SExpr::UNOP: {
        const uint64_t a = evalExpr(pi, *e.a);
        const Varnode* va = pi.find(a);
        if (e.op == '~') {
            if (va && va->isConst()) {
                Varnode* v = makeVarnode(pi, Varnode::CONST, ~va->offset, 8);
                return v->id;
            }
            Varnode* m1 = makeVarnode(pi, Varnode::CONST, ~0ULL, 8);
            Varnode* out = makeVarnode(pi, Varnode::UNIQUE, nextId_++, 8);
            pi.ops.push_back(PcodeOp{POp::INT_XOR, out->id, a, m1->id, 0});
            return out->id;
        }
        if (e.op == '-') {
            if (va && va->isConst()) {
                Varnode* v = makeVarnode(
                    pi, Varnode::CONST,
                    static_cast<uint64_t>(-static_cast<int64_t>(va->offset)), 8);
                return v->id;
            }
            Varnode* out = makeVarnode(pi, Varnode::UNIQUE, nextId_++, 8);
            pi.ops.push_back(PcodeOp{POp::INT_NEGATE, out->id, a, 0, 0});
            return out->id;
        }
        // '!' -> BOOL_NEGATE
        if (va && va->isConst()) {
            Varnode* v = makeVarnode(pi, Varnode::CONST, va->offset ? 0 : 1, 1);
            return v->id;
        }
        Varnode* out = makeVarnode(pi, Varnode::UNIQUE, nextId_++, 1);
        pi.ops.push_back(PcodeOp{POp::BOOL_NEGATE, out->id, a, 0, 0});
        return out->id;
    }
    case SpecCtor::SExpr::SEXT: {
        const uint64_t a = evalExpr(pi, *e.a);
        const Varnode* va = pi.find(a);
        const int srcBits = e.bits ? e.bits : (va ? va->size * 8 : 8);
        if (va && va->isConst()) {
            const uint64_t sign = 1ULL << (srcBits - 1);
            const uint64_t mask =
                (srcBits >= 64) ? ~0ULL : ((1ULL << srcBits) - 1);
            const uint64_t v = ((va->offset & mask) ^ sign) - sign;
            Varnode* v2 = makeVarnode(pi, Varnode::CONST, v, 8);
            return v2->id;
        }
        Varnode* lo = makeVarnode(pi, Varnode::UNIQUE, nextId_++,
                                  (srcBits + 7) / 8);
        pi.ops.push_back(PcodeOp{POp::SUBPIECE, lo->id, a, 0, 0});
        Varnode* out = makeVarnode(pi, Varnode::UNIQUE, nextId_++, 8);
        pi.ops.push_back(PcodeOp{POp::INT_SEXT, out->id, lo->id, 0, 0});
        return out->id;
    }
    case SpecCtor::SExpr::ZEXT: {
        const uint64_t a = evalExpr(pi, *e.a);
        const Varnode* va = pi.find(a);
        const int srcBits = e.bits ? e.bits : (va ? va->size * 8 : 8);
        if (va && va->isConst()) {
            const uint64_t mask =
                (srcBits >= 64) ? ~0ULL : ((1ULL << srcBits) - 1);
            Varnode* v2 = makeVarnode(pi, Varnode::CONST, va->offset & mask, 8);
            return v2->id;
        }
        Varnode* out = makeVarnode(pi, Varnode::UNIQUE, nextId_++,
                                   (srcBits + 7) / 8);
        pi.ops.push_back(PcodeOp{POp::INT_ZEXT, out->id, a, 0, 0});
        return out->id;
    }
    case SpecCtor::SExpr::LOAD: {
        const uint64_t a = evalExpr(pi, *e.a);
        const int sz = e.bits ? e.bits : (x86Opsz_ ? x86Opsz_ : 8);
        Varnode* out = makeVarnode(pi, Varnode::UNIQUE, nextId_++, sz);
        pi.ops.push_back(PcodeOp{POp::LOAD, out->id, a, 0, 0});
        return out->id;
    }
    }
    return constVarnode(pi, 0, 8);
}

// ---------------------------------------------------------------------------
// disassembly

bool SleighEngine::disassemble(
    const std::function<bool(uint64_t, void*, size_t)>& read, uint64_t addr,
    PcodeInsn& out, std::string& err) const {
    const int maxTok = tokenSize();
    if (maxTok <= 0) return false;
    uint8_t raw[16];
    int got = 0;
    for (int n : {maxTok, maxTok / 2, maxTok / 4, 1}) {
        if (n <= 0) continue;
        if (read(addr, raw, static_cast<size_t>(n))) {
            got = n;
            break;
        }
    }
    if (got == 0) return false;

    // ---- x86: consume prefixes and set context (REX/66/67/... ) ----
    struct X86Ctx {
        bool rex = false, rexw = false, rexr = false, rexx = false,
             rexb = false, op66 = false, addr67 = false;
        int opsz = 4; // operand size in bytes
        int prefixLen = 0;
        bool haveModrm = false;
        int mod = 0, reg = 0, rm = 0;
        int cursor = 0; // next unread byte in the token word
        bool isMem = false, ripRel = false;
        int64_t disp = 0;
        int base = -1, index = -1, scale = 1;
        int regReg = 0; // reg-field register idx (+REX.R)
        int rmReg = 0;  // rm register idx (mod==3, +REX.B)
    } xc;
    if (archX86_) {
        int p = 0;
        while (p < got) {
            const uint8_t b = raw[p];
            if (b == 0x66) { xc.op66 = true; p++; }
            else if (b == 0x67) { xc.addr67 = true; p++; }
            else if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E ||
                     b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 ||
                     b == 0x65) {
                p++;
            } else if (b >= 0x40 && b <= 0x4F) {
                xc.rex = true;
                xc.rexw = b & 8;
                xc.rexr = b & 4;
                xc.rexx = b & 2;
                xc.rexb = b & 1;
                p++;
            } else {
                break;
            }
        }
        xc.prefixLen = p;
        xc.opsz = xc.rexw ? 8 : (xc.op66 ? 2 : 4);
        x86Opsz_ = xc.opsz;
    }

    // little-endian word per token (missing tail bytes read as zero)
    uint64_t word[4] = {0, 0, 0, 0};
    for (size_t t = 0; t < tokens_.size(); ++t) {
        const int avail = std::min(tokens_[t].size, got - xc.prefixLen);
        for (int i = 0; i < avail; ++i)
            word[t] |= static_cast<uint64_t>(raw[xc.prefixLen + i]) << (8 * i);
    }

    auto fieldValue = [&](const SpecField& f) -> uint64_t {
        uint64_t v = 0;
        const uint64_t w = word[f.token];
        for (const auto& pc : f.pieces) {
            const int width = pc.msb - pc.lsb + 1;
            const uint64_t mask =
                (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
            v |= ((w >> pc.lsb) & mask) << pc.shift;
        }
        return v;
    };

    // ---- x86 magic terms ----
    std::vector<std::pair<std::string, std::string>> magicExports;
    auto isMagic = [&](const std::string& n) {
        return archX86_ &&
               (n == "rexw" || n == "opsz" || n == "modrm" ||
                n.rfind("modrm", 0) == 0 || n == "rreg" ||
                n.rfind("rreg", 0) == 0 || n == "rmreg" ||
                n.rfind("rmreg", 0) == 0 || n == "rmmem" ||
                n == "rmval" || n.rfind("rmval", 0) == 0 || n == "ea" ||
                n == "rq" || n.rfind("rq", 0) == 0 || n == "immb" ||
                n == "immw" || n == "immd" || n == "immq" || n == "immv" ||
                n == "immz");
    };
    auto magicSize = [&](const std::string& n) {
        // trailing digits carry the size: rreg8, rmreg16, rq64, rmval32
        const char* d = n.c_str();
        while (*d && !isdigit(static_cast<unsigned char>(*d))) d++;
        return *d ? atoi(d) : xc.opsz;
    };

    auto readByte = [&](int off) -> uint8_t {
        return (off >= 0 && off < maxTok) ? ((word[0] >> (8 * off)) & 0xFF)
                                          : 0;
    };
    auto decodeModrm = [&](int off) -> bool {
        xc.haveModrm = true;
        const uint8_t b = readByte(off);
        xc.mod = (b >> 6) & 3;
        xc.reg = (b >> 3) & 7;
        xc.rm = b & 7;
        xc.cursor = off + 1;
        xc.regReg = xc.reg | (xc.rexr ? 8 : 0);
        if (xc.mod == 3) {
            xc.isMem = false;
            xc.rmReg = xc.rm | (xc.rexb ? 8 : 0);
            return true;
        }
        xc.isMem = true;
        const bool addr64 = !xc.addr67;
        const int rm = xc.rm;
        int64_t disp = 0;
        int base = -1, index = -1, scale = 1;
        if (addr64) {
            if (rm == 4) {
                const uint8_t sib = readByte(xc.cursor);
                xc.cursor++;
                scale = 1 << ((sib >> 6) & 3);
                const int idx = (sib >> 3) & 7, bs = sib & 7;
                if (idx != 4) index = idx | (xc.rexx ? 8 : 0);
                if (!(bs == 5 && xc.mod == 0)) base = bs | (xc.rexb ? 8 : 0);
            } else if (rm == 5 && xc.mod == 0) {
                xc.ripRel = true;
            } else {
                base = rm | (xc.rexb ? 8 : 0);
            }
        } else {
            if (rm == 4) {
                const uint8_t sib = readByte(xc.cursor);
                xc.cursor++;
                scale = 1 << ((sib >> 6) & 3);
                const int idx = (sib >> 3) & 7, bs = sib & 7;
                if (idx != 4) index = idx;
                if (!(bs == 5 && xc.mod == 0)) base = bs;
            } else if (rm == 5 && xc.mod == 0) {
                // disp32 absolute, no base
            } else {
                base = rm;
            }
        }
        if (xc.mod == 1) {
            disp = static_cast<int8_t>(readByte(xc.cursor));
            xc.cursor++;
        } else if (xc.mod == 2) {
            uint32_t v = 0;
            for (int i = 0; i < 4; ++i) v |= (uint32_t)readByte(xc.cursor + i) << (8 * i);
            xc.cursor += 4;
            disp = static_cast<int32_t>(v);
        } else if (xc.mod == 0 &&
                   ((addr64 && ((rm == 5) || (rm == 4 && base == -1))) ||
                    (!addr64 && rm == 5))) {
            uint32_t v = 0;
            for (int i = 0; i < 4; ++i) v |= (uint32_t)readByte(xc.cursor + i) << (8 * i);
            xc.cursor += 4;
            disp = static_cast<int32_t>(v);
        }
        xc.base = base;
        xc.index = index;
        xc.scale = scale;
        xc.disp = disp;
        return true;
    };

    // first full pattern match wins (declaration order)
    const SpecCtor* matched = nullptr;
    int insnSize = maxTok;
    std::map<std::string, uint64_t> opValues;
    std::map<std::string, std::string> opFields; // operand -> token field
    for (const auto& c : ctors_) {
        bool ok = true;
        int usedTok = 0;
        opValues.clear();
        opFields.clear();
        magicExports.clear();
        for (const auto& t : c.terms) {
            const std::string& fn = t.field;
            if (isMagic(fn)) {
                if (fn == "rexw" || fn == "opsz") {
                    const uint64_t v =
                        (fn == "rexw") ? (xc.rexw ? 1 : 0)
                                        : static_cast<uint64_t>(xc.opsz);
                    if (t.kind == SpecCtor::Term::FIELD_EQ && v != t.value) {
                        ok = false;
                        break;
                    }
                    continue;
                }
                if (fn == "modrm" || fn.rfind("modrm", 0) == 0) {
                    int off = 1;
                    if (fn.size() > 5) off = atoi(fn.c_str() + 5);
                    if (!decodeModrm(off)) { ok = false; break; }
                    continue;
                }
                // FIELD_EQ on register exports: /digit group check
                if (t.kind == SpecCtor::Term::FIELD_EQ &&
                    (fn.rfind("rreg", 0) == 0 || fn.rfind("rmreg", 0) == 0 ||
                     fn.rfind("rq", 0) == 0)) {
                    int idx = xc.regReg;
                    if (fn.rfind("rmreg", 0) == 0) idx = xc.rmReg;
                    else if (fn.rfind("rq", 0) == 0)
                        idx = (readByte(0) & 7) | (xc.rexb ? 8 : 0);
                    if (idx != static_cast<int>(t.value)) {
                        ok = false;
                        break;
                    }
                    continue;
                }
                // export terms: register/ea/imm materialized after match
                if (fn.rfind("rmreg", 0) == 0 &&
                    (!xc.haveModrm || xc.mod != 3)) {
                    ok = false;
                    break;
                }
                if (fn == "rmmem" && (!xc.haveModrm || xc.mod == 3)) {
                    ok = false;
                    break;
                }
                if ((fn == "rreg" || fn.rfind("rreg", 0) == 0 || fn == "ea") &&
                    !xc.haveModrm) {
                    ok = false;
                    break;
                }
                // advance the byte cursor for immediates during matching
                // (the instruction size depends on it)
                if (fn == "immb") xc.cursor += 1;
                else if (fn == "immw") xc.cursor += 2;
                else if (fn == "immd") xc.cursor += 4;
                else if (fn == "immq") xc.cursor += 8;
                else if (fn == "immv") xc.cursor += xc.opsz;
                else if (fn == "immz") xc.cursor += xc.op66 ? 2 : 4;
                magicExports.emplace_back(t.operand, fn);
                continue;
            }
            const SpecField* f = findField(fn);
            if (!f) { ok = false; break; }
            usedTok = std::max(usedTok, tokens_[f->token].size);
            const uint64_t v = fieldValue(*f);
            if (t.kind == SpecCtor::Term::FIELD_EQ) {
                if (v != t.value) { ok = false; break; }
                // x86: advance the imm cursor past matched opcode bytes
                if (archX86_) {
                    if (fn == "opcode") xc.cursor = std::max(xc.cursor, 1);
                    else if (fn == "op2") xc.cursor = std::max(xc.cursor, 2);
                    else if (fn == "op3") xc.cursor = std::max(xc.cursor, 3);
                }
            } else {
                opValues[t.operand] = v;
                opFields[t.operand] = t.field;
            }
        }
        if (ok) {
            matched = &c;
            insnSize = archX86_ ? (xc.prefixLen + xc.cursor)
                                : std::max(usedTok, 1);
            break;
        }
    }
    if (!matched) return false;

    out = PcodeInsn{};
    out.addr = addr;
    out.size = insnSize;
    out.nextAddr = addr + insnSize;
    nextId_ = 1;
    cache_.clear();

    // ---- x86 helpers (need `out` and insnSize) ----
    auto x86RegVarnode = [&](int idx, int size) -> uint64_t {
        char nm[8];
        if (size == 1) {
            static const char* r8lo[8] = {"al", "cl", "dl", "bl",
                                          "spl", "bpl", "sil", "dil"};
            static const char* r8hi[8] = {"al", "cl", "dl", "bl",
                                          "ah", "ch", "dh", "bh"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "r%db", idx);
            else if (xc.rex && idx >= 4)
                std::snprintf(nm, sizeof(nm), "%s", r8lo[idx]);
            else
                std::snprintf(nm, sizeof(nm), "%s", r8hi[idx]);
        } else if (size == 2) {
            static const char* r16[8] = {"ax", "cx", "dx", "bx",
                                         "sp", "bp", "si", "di"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "r%dw", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", r16[idx]);
        } else if (size == 4) {
            static const char* r32[8] = {"eax", "ecx", "edx", "ebx",
                                         "esp", "ebp", "esi", "edi"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "r%dd", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", r32[idx]);
        } else {
            static const char* r64[8] = {"rax", "rcx", "rdx", "rbx",
                                         "rsp", "rbp", "rsi", "rdi"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "r%d", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", r64[idx]);
        }
        Varnode* v = makeVarnode(out, Varnode::REGISTER,
                                 static_cast<uint64_t>(idx) * 8, size, nm);
        return v->id;
    };
    auto addrText = [&]() -> std::string {
        std::string s = "[";
        bool any = false;
        auto rn = [&](int idx) {
            char b[8];
            std::snprintf(b, sizeof(b), "r%d", idx);
            static const char* r64[8] = {"rax", "rcx", "rdx", "rbx",
                                         "rsp", "rbp", "rsi", "rdi"};
            return idx >= 8 ? std::string(b) : std::string(r64[idx]);
        };
        if (xc.ripRel) {
            char b[24];
            std::snprintf(b, sizeof(b), "0x%llx",
                          static_cast<unsigned long long>(addr + insnSize +
                                                          xc.disp));
            return b;
        }
        if (xc.base >= 0) {
            s += rn(xc.base);
            any = true;
        }
        if (xc.index >= 0) {
            if (any) s += " + ";
            s += rn(xc.index);
            if (xc.scale > 1) s += "*" + std::to_string(xc.scale);
            any = true;
        }
        if (xc.disp != 0 || !any) {
            if (any) {
                s += xc.disp >= 0 ? " + " : " - ";
                char b[24];
                std::snprintf(b, sizeof(b), "0x%llx",
                              static_cast<unsigned long long>(
                                  xc.disp < 0 ? -xc.disp : xc.disp));
                s += b;
            } else {
                char b[24];
                std::snprintf(b, sizeof(b), "0x%llx",
                              static_cast<unsigned long long>(xc.disp));
                s += b;
            }
        }
        s += "]";
        return s;
    };
    auto materializeAddr = [&]() -> uint64_t {
        if (xc.ripRel) {
            Varnode* v = makeVarnode(out, Varnode::CONST,
                                     addr + insnSize + xc.disp, 8);
            return v->id;
        }
        std::vector<uint64_t> parts;
        if (xc.base >= 0) parts.push_back(x86RegVarnode(xc.base, 8));
        if (xc.index >= 0) {
            uint64_t v = x86RegVarnode(xc.index, 8);
            if (xc.scale > 1) {
                Varnode* t = makeVarnode(out, Varnode::UNIQUE, nextId_++, 8);
                out.ops.push_back(PcodeOp{POp::INT_MULT, t->id, v,
                                          constVarnode(out, xc.scale, 8), 0});
                v = t->id;
            }
            parts.push_back(v);
        }
        if (xc.disp != 0) {
            Varnode* c = makeVarnode(out, Varnode::CONST,
                                     static_cast<uint64_t>(xc.disp), 8);
            parts.push_back(c->id);
        }
        if (parts.empty()) return constVarnode(out, 0, 8);
        uint64_t acc = parts[0];
        for (size_t i = 1; i < parts.size(); ++i) {
            Varnode* t = makeVarnode(out, Varnode::UNIQUE, nextId_++, 8);
            out.ops.push_back(PcodeOp{POp::INT_ADD, t->id, acc, parts[i], 0});
            acc = t->id;
        }
        return acc;
    };

    // materialize magic exports (registers, addresses, immediates)
    for (const auto& [opname, mname] : magicExports) {
        if (mname == "rreg" || mname.rfind("rreg", 0) == 0) {
            out.named[opname] = x86RegVarnode(xc.regReg, magicSize(mname));
        } else if (mname == "rmreg" || mname.rfind("rmreg", 0) == 0) {
            out.named[opname] = x86RegVarnode(xc.rmReg, magicSize(mname));
        } else if (mname == "rq" || mname.rfind("rq", 0) == 0) {
            const int idx = (readByte(0) & 7) | (xc.rexb ? 8 : 0);
            out.named[opname] = x86RegVarnode(idx, magicSize(mname));
        } else if (mname == "rmmem") {
            const uint64_t ea = materializeAddr();
            auto it = out.varnodes.find(ea);
            if (it != out.varnodes.end() && it->second.kind == Varnode::UNIQUE)
                it->second.name = addrText();
            out.named[opname] = ea;
        } else if (mname == "ea") {
            out.named[opname] = materializeAddr();
        } else if (mname == "rmval" || mname.rfind("rmval", 0) == 0) {
            const int size = magicSize(mname);
            if (!xc.isMem) {
                out.named[opname] = x86RegVarnode(xc.rmReg, size);
            } else {
                const uint64_t ea = materializeAddr();
                Varnode* t = makeVarnode(out, Varnode::UNIQUE, nextId_++, size);
                t->name = addrText();
                out.ops.push_back(PcodeOp{POp::LOAD, t->id, ea, 0, 0});
                out.named[opname] = t->id;
            }
        } else if (mname == "immb" || mname == "immw" || mname == "immd" ||
                   mname == "immq" || mname == "immv" || mname == "immz") {
            const int n = mname == "immb" ? 1
                          : mname == "immw" ? 2
                          : mname == "immd" ? 4
                          : mname == "immq" ? 8
                          : mname == "immz" ? (xc.op66 ? 2 : 4)
                                            : xc.opsz;
            uint64_t v = 0;
            // cursor was advanced during matching; read the bytes before it
            for (int i = 0; i < n; ++i)
                v |= static_cast<uint64_t>(readByte(xc.cursor - n + i))
                     << (8 * i);
            // cursor was already advanced during matching
            Varnode* c = makeVarnode(out, Varnode::CONST, v, n);
            out.named[opname] = c->id;
        }
    }

    // create operand varnodes (named for semantics + rendering)
    for (const auto& oname : matched->operands) {
        if (out.named.count(oname)) continue; // magic export already made
        auto it = opValues.find(oname);
        if (it == opValues.end()) continue; // e.g. 'rd=1' not exported
        const SpecField* f = nullptr;
        {
            auto fi = opFields.find(oname);
            if (fi != opFields.end()) f = findField(fi->second);
        }
        if (!f) f = findField(oname);
        if (f && f->attached) {
            const uint64_t idx = it->second;
            if (idx < f->regs.size()) {
                if (const SpecRegister* r = findReg(f->regs[idx])) {
                    const uint64_t id = regVarnode(out, *r);
                    out.named[oname] = id;
                }
            }
        } else {
            // store sign-extended value so both rendering and semantics
            // agree (spec-level sext() of an already-sextended value is
            // idempotent)
            int64_t sv = static_cast<int64_t>(it->second);
            if (f && f->bits > 0 && f->bits < 64) {
                const uint64_t sign = 1ULL << (f->bits - 1);
                const uint64_t mask = (1ULL << f->bits) - 1;
                sv = static_cast<int64_t>(((it->second & mask) ^ sign) - sign);
            }
            Varnode* v = makeVarnode(out, Varnode::CONST,
                                     static_cast<uint64_t>(sv),
                                     f ? f->size : 8);
            out.named[oname] = v->id;
        }
    }

    // emit semantics
    for (const auto& st : matched->stmts) {
        switch (st.kind) {
        case SpecCtor::SStmt::ASSIGN: {
            const uint64_t rhs = evalExpr(out, *st.rhsE);
            uint64_t lhs = 0;
            {
                auto it = out.named.find(st.lhs);
                if (it != out.named.end()) lhs = it->second;
            }
            if (!lhs) {
                if (const SpecRegister* r = findReg(st.lhs))
                    lhs = regVarnode(out, *r);
                else {
                    Varnode* t = makeVarnode(out, Varnode::UNIQUE, nextId_++,
                                             8, st.lhs);
                    out.named[st.lhs] = t->id;
                    lhs = t->id;
                }
            }
            out.ops.push_back(PcodeOp{POp::COPY, lhs, rhs, 0, 0});
            break;
        }
        case SpecCtor::SStmt::GOTO: {
            const uint64_t dest = evalExpr(out, *st.rhsE);
            out.ops.push_back(PcodeOp{POp::BRANCH, 0, dest, 0, 0});
            break;
        }
        case SpecCtor::SStmt::CGOTO: {
            const uint64_t cond = evalExpr(out, *st.condE);
            const uint64_t dest = evalExpr(out, *st.rhsE);
            out.ops.push_back(PcodeOp{POp::CBRANCH, 0, dest, cond, 0});
            break;
        }
        case SpecCtor::SStmt::CALL: {
            const uint64_t dest = evalExpr(out, *st.rhsE);
            out.ops.push_back(PcodeOp{POp::CALL, 0, dest, 0, 0});
            break;
        }
        case SpecCtor::SStmt::RET:
            out.ops.push_back(PcodeOp{POp::RETURN, 0, 0, 0, 0});
            break;
        case SpecCtor::SStmt::STORE: {
            const uint64_t addrId = evalExpr(out, *st.lhsE);
            const uint64_t valId = evalExpr(out, *st.rhsE);
            out.ops.push_back(PcodeOp{POp::STORE, 0, addrId, 0, valId});
            break;
        }
        }
    }

    // classify + resolve branch/call targets
    out.kind = Insn::OTHER;
    out.target = 0;
    out.targetKnown = false;
    for (const auto& op : out.ops) {
        const Varnode* vd = out.find(op.in0);
        const bool constDest = vd && vd->isConst();
        switch (op.op) {
        case POp::RETURN:
            out.kind = Insn::RET;
            break;
        case POp::CALL:
            out.kind = Insn::CALL;
            if (constDest) {
                out.target = vd->offset;
                out.targetKnown = true;
            }
            break;
        case POp::BRANCH:
            if (out.kind == Insn::OTHER) {
                out.kind = Insn::JMP;
                if (constDest) {
                    out.target = vd->offset;
                    out.targetKnown = true;
                }
            }
            break;
        case POp::CBRANCH:
            out.kind = Insn::JCC;
            if (constDest) {
                out.target = vd->offset;
                out.targetKnown = true;
            }
            break;
        default:
            break;
        }
    }

    // ---- render text ----
    auto fmtImm = [](int64_t v) -> std::string {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
        return buf;
    };
    auto hexAddr = [](uint64_t a) -> std::string {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(a));
        return buf;
    };
    auto operandText = [&](const std::string& oname) -> std::string {
        auto it = out.named.find(oname);
        if (it == out.named.end()) return "";
        const Varnode* v = out.find(it->second);
        if (!v) return "";
        if (v->kind == Varnode::REGISTER) return v->name;
        return fmtImm(static_cast<int64_t>(v->offset));
    };

    static const std::set<std::string> memOps = {
        "lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "sb", "sh", "sw", "sd"};
    static const std::set<std::string> spOps = {"c.lwsp", "c.ldsp",
                                                 "c.swsp", "c.sdsp"};
    const bool isMem = memOps.count(matched->name) != 0;
    const bool isJalr = matched->name == "jalr";
    const bool isSp = spOps.count(matched->name) != 0;

    std::vector<std::string> parts;
    for (const auto& oname : matched->operands) {
        const std::string s = operandText(oname);
        if (!s.empty()) parts.push_back(s);
    }

    std::string text = matched->name;
    if (isSp && parts.size() >= 2) {
        // "c.lwsp rd, imm(sp)"
        text += " " + parts[0] + ", " + parts[1] + "(sp)";
    } else if (isMem || isJalr) {
        // "mnem a, c(b)"  where a=rd/rs2, b=rs1, c=imm
        if (parts.size() >= 3) {
            text += " " + parts[0] + ", " + parts[2] + "(" + parts[1] + ")";
        } else if (parts.size() == 1) {
            text += " " + parts[0];
        }
    } else {
        for (size_t i = 0; i < parts.size(); ++i)
            text += (i == 0 ? " " : ", ") + parts[i];
    }
    // branches/calls: absolute target address
    if (out.targetKnown &&
        (out.kind == Insn::JMP || out.kind == Insn::JCC ||
         out.kind == Insn::CALL)) {
        const size_t pos = text.rfind(", ");
        if (pos != std::string::npos)
            text = text.substr(0, pos + 2) + hexAddr(out.target);
        else
            text = matched->name + std::string(" ") + hexAddr(out.target);
    }
    out.text = text;
    return true;
}

// ---------------------------------------------------------------------------
// SpecDisassembler adapter

bool SpecDisassembler::disasmOne(const MemoryImage& mem, uint64_t addr,
                                 Insn& out) {
    auto read = [&](uint64_t a, void* buf, size_t n) {
        return mem.read(a, buf, n);
    };
    PcodeInsn pi;
    std::string err;
    if (!eng_->disassemble(read, addr, pi, err)) return false;
    out.addr = addr;
    out.size = pi.size;
    out.bytes.resize(pi.size);
    if (!mem.read(addr, out.bytes.data(), out.bytes.size())) return false;
    out.text = pi.text;
    out.kind = pi.kind;
    out.target = pi.target;
    out.targetKnown = pi.targetKnown;
    return true;
}

std::string SpecDisassembler::backendName() const {
    return "sleigh-lite (" + eng_->tokenName() + ")";
}

} // namespace ghra
