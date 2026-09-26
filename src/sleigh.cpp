// centrifuge - a Ghidra reimplementation in C++17
// sleigh.cpp - SLEIGH-lite: spec parsing, pattern matching, p-code emission
//
// Operator encoding for expression trees (unique int codes):
//   '+','-','*','/','%','&','|','^'  single chars
//   '<','>','==','!=','<=','>='       char pairs (hi<<8|lo)
//   's<','s>','s<=','s>=','s>>','s/','s%'  signed: 0x40000000 | code
//   '<<' 0x3C3C   '>>' 0x3E3E
#include "centrifuge/sleigh.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <set>
#include <sstream>

namespace centrifuge {

thread_local int SleighEngine::x86Opsz_ = 0;
thread_local uint64_t SleighEngine::nextId_ = 1;
thread_local std::map<uint64_t, Varnode>* SleighEngine::cache_ = nullptr;

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
    (void)err;
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
        if (isId(peek(), "select")) {
            i++;
            if (!eatOp("(")) { err = "expected ( after select"; return {}; }
            auto cond = parseExpr();
            if (!eatOp(",")) { err = "expected first , in select"; return {}; }
            auto yes = parseExpr();
            if (!eatOp(",")) { err = "expected second , in select"; return {}; }
            auto no = parseExpr();
            if (!eatOp(")")) { err = "expected ) after select"; return {}; }
            auto e = std::make_unique<SExpr>();
            e->kind = SExpr::SELECT;
            e->a = std::move(cond);
            e->b = std::move(yes);
            e->c = std::move(no);
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
#ifdef CENTRIFUGE_DEBUG_TOKENS
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
        for (const auto& ct : c.terms) {
            if (ct.field.rfind("evex", 0) == 0) c.requiresEvex = true;
            else if (ct.field.rfind("vex", 0) == 0) c.requiresVex = true;
        }
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
    auto& cache = *cache_;
    auto it = cache.find(key);
    if (it != cache.end()) {
        pi.varnodes[it->second.id] = it->second;
        return it->second.id;
    }
    Varnode* v = makeVarnode(pi, Varnode::REGISTER, r.offset, r.size, r.name);
    cache[key] = *v;
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
        const bool comparison =
            pop == POp::INT_EQUAL || pop == POp::INT_NOTEQUAL ||
            pop == POp::INT_LESS || pop == POp::INT_SLESS ||
            pop == POp::INT_LESSEQUAL || pop == POp::INT_SLESSEQUAL;
        const int outSize = comparison ? 1 : (va && va->size ? va->size : 8);
        Varnode* out = makeVarnode(pi, Varnode::UNIQUE, nextId_++, outSize);
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
    case SpecCtor::SExpr::SELECT: {
        const uint64_t cond = evalExpr(pi, *e.a);
        const uint64_t yes = evalExpr(pi, *e.b);
        const uint64_t no = evalExpr(pi, *e.c);
        const Varnode* vy = pi.find(yes);
        const Varnode* vn = pi.find(no);
        const int sz = vy && vy->size ? vy->size : (vn && vn->size ? vn->size : 8);
        Varnode* out = makeVarnode(pi, Varnode::UNIQUE, nextId_++, sz);
        pi.ops.push_back(PcodeOp{POp::SELECT, out->id, cond, yes, no});
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
    std::map<uint64_t, Varnode> instructionCache;
    cache_ = &instructionCache;
    (void)err;
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
             rexb = false, op66 = false, opF2 = false, opF3 = false,
             addr67 = false;
        int segmentOverride = -1; // 4=FS, 5=GS; other x64 segments are flat
        bool vex = false;
        int vexMap = 1;   // 1=0F, 2=0F38, 3=0F3A
        int vexVvvv = -1; // 0-15, -1 = unused
        bool vexW = false, vexL = false;
        int vexPP = 0;
        bool evex = false;
        int evexMap = 1;   // 1=0F, 2=0F38, 3=0F3A
        int evexVvvv = -1; // 0-31, -1 = unused
        bool evexW = false;
        int evexL = 0;     // 0=xmm, 1=ymm, 2=zmm
        int evexPP = 0;
        bool evexZ = false, evexB = false;
        int evexAaa = 0;
        int evexRprime = 0; // ~R'<<4, extends reg field to 5 bits
        int evexVprime = 0; // ~V'<<4, extends VSIB vector index
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
            else if (b == 0xF0) { p++; }
            else if (b == 0xF2) { xc.opF2 = true; p++; }
            else if (b == 0xF3) { xc.opF3 = true; p++; }
            else if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                     b == 0x64 || b == 0x65) {
                if (b == 0x64) xc.segmentOverride = 4;
                else if (b == 0x65) xc.segmentOverride = 5;
                p++;
            }
            else if (b == 0xC5 && p + 1 < got) {
                // VEX2: R ~vvvv L pp (map=0F, no W bit -> implied 0)
                // pp: 0=0F 1=66 2=F3 3=F2; L: 0=xmm 1=ymm
                const uint8_t b2 = raw[p + 1];
                xc.vex = true;
                xc.rexr = !(b2 >> 7) & 1;
                xc.rexb = false;
                xc.rexx = false;
                xc.vexVvvv = (~((b2 >> 3) & 0xF)) & 0xF;
                xc.vexW = false;
                xc.vexL = (b2 >> 2) & 1;
                xc.vexPP = b2 & 3;
                xc.vexMap = 1;
                p += 2;
                break; // VEX is self-contained
            }
            else if (b == 0xC4 && p + 2 < got) {
                // VEX3: R X B mmmmm | vvvv W L pp
                const uint8_t b2 = raw[p + 1];
                const uint8_t b3 = raw[p + 2];
                xc.vex = true;
                xc.rexr = !(b2 >> 7) & 1;
                xc.rexx = !((b2 >> 6) & 1);
                xc.rexb = !((b2 >> 5) & 1);
                xc.vexMap = b2 & 0x1F;
                xc.vexVvvv = (~((b3 >> 3) & 0xF)) & 0xF;
                xc.vexW = (b3 >> 7) & 1;
                xc.vexL = (b3 >> 2) & 1;
                xc.vexPP = b3 & 3;
                p += 3;
                break; // VEX is self-contained; no prefixes after it
            }
            else if (b == 0x62 && p + 3 < got) {
                // EVEX: P0=[R][X][B][R'][0][mm] P1=[W][vvvv][1][pp]
                //       P2=[z][LL][b][V'][aaa]
                const uint8_t p0 = raw[p + 1];
                const uint8_t p1 = raw[p + 2];
                const uint8_t p2 = raw[p + 3];
                xc.evex = true;
                xc.rexr = !((p0 >> 7) & 1);
                xc.rexx = !((p0 >> 6) & 1);
                xc.rexb = !((p0 >> 5) & 1);
                xc.evexRprime = (!((p0 >> 4) & 1)) ? 16 : 0;
                xc.evexVprime = (!((p2 >> 3) & 1)) ? 16 : 0;
                xc.evexMap = p0 & 7;
                xc.evexW = (p1 >> 7) & 1;
                xc.evexVvvv =
                    (~((((p2 >> 3) & 1) << 4) | ((p1 >> 3) & 0xF))) & 0x1F;
                xc.evexL = (p2 >> 5) & 3;
                xc.evexPP = p1 & 3;
                xc.evexZ = (p2 >> 7) & 1;
                xc.evexB = (p2 >> 4) & 1;
                xc.evexAaa = p2 & 7;
                p += 4;
                break; // EVEX is self-contained
            }
            else if (b >= 0x40 && b <= 0x4F) {
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
        // A token may describe a 15-byte x86 instruction, while field
        // extraction uses a 64-bit window.  Fields in the x86 spec live in
        // the leading bytes; never shift a uint64_t by 64 or more here.
        for (int i = 0; i < std::min(avail, 8); ++i)
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
               (n == "rregv" || n == "rmregv" || n == "rregmm" ||
                n == "rmregmm" || n.rfind("acc", 0) == 0 ||
                n == "vex" ||
                n == "vexmap" ||
                n == "vexvvvv" || n.rfind("vexvvvv", 0) == 0 ||
                n == "vexw" || n == "vexL" || n == "vexpp" ||
                n == "evex" || n == "evexmap" || n == "evexw" ||
                n == "evexL" || n == "evexpp" || n == "evexvvvv" ||
                n.rfind("evexvvvv", 0) == 0 || n == "evexz" ||
                n == "evexb" || n == "evexaaa" ||
                n == "pfxf2" || n == "pfxf3" || n == "pfx66" ||
                n == "pfxnone" || n == "rexw" || n == "opsz" || n == "modrm" ||
                n.rfind("modrm", 0) == 0 || n == "rreg" ||
                n.rfind("rreg", 0) == 0 || n == "rmreg" ||
                n.rfind("rmreg", 0) == 0 || n.rfind("rmmem", 0) == 0 ||
                n == "rmval" || n.rfind("rmval", 0) == 0 || n == "sreg" || n == "ea" ||
                n == "rq" || n.rfind("rq", 0) == 0 || n == "immb" ||
                n == "immw" || n == "immd" || n == "immq" || n == "immv" ||
                n == "immz");
    };
    auto magicSize = [&](const std::string& n) {
        // trailing digits carry the size: rreg8, rmreg16, rq64, rmval32
        const char* d = n.c_str();
        while (*d && !isdigit(static_cast<unsigned char>(*d))) d++;
        return *d ? atoi(d) / 8 : xc.opsz;
    };

    auto readByte = [&](int off) -> uint8_t {
        const int rawOffset = xc.prefixLen + off;
        return (off >= 0 && rawOffset >= 0 && rawOffset < got)
                   ? raw[rawOffset]
                   : 0;
    };
    auto decodeModrm = [&](int off) -> bool {
        xc.haveModrm = true;
        const uint8_t b = readByte(off);
        xc.mod = (b >> 6) & 3;
        xc.reg = (b >> 3) & 7;
        xc.rm = b & 7;
        xc.cursor = off + 1;
        xc.regReg = xc.reg | (xc.rexr ? 8 : 0) |
                    (xc.evex ? xc.evexRprime : 0);
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
                // SIB index=4 means "no index" only when X is clear.  With
                // REX.X/VEX.X/EVEX.X set the same encoding names r12; dropping
                // it turned LEA [rbx+r12] into LEA [rbx] and broke loop
                // progress in real x64 programs.
                if (idx != 4 || xc.rexx)
                    index = idx | (xc.rexx ? 8 : 0);
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
                if (idx != 4 || xc.rexx)
                    index = idx | (xc.rexx ? 8 : 0);
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
        // ModRM/immediate decoding is constructor-local.  A failed candidate
        // must not leave its cursor or addressing state in the next match.
        xc.cursor = 0;
        xc.haveModrm = false;
        xc.mod = xc.reg = xc.rm = 0;
        xc.isMem = xc.ripRel = false;
        xc.disp = 0;
        xc.base = xc.index = -1;
        xc.scale = 1;
        xc.regReg = xc.rmReg = 0;
        bool ok = true;
        int usedTok = 0;
        const char* dbgFail = nullptr;
        opValues.clear();
        opFields.clear();
        magicExports.clear();
        if (c.requiresEvex) {
            if (!xc.evex) continue;
        } else if (c.requiresVex) {
            if (!xc.vex || xc.evex) continue;
        } else if (xc.vex || xc.evex) {
            continue;
        }
        for (const auto& t : c.terms) {
            const std::string& fn = t.field;
            dbgFail = fn.c_str();
            if (isMagic(fn)) {
                if (fn == "vex") {
                    if (!xc.vex) { ok = false; break; }
                    continue;
                }
                if (fn == "vexmap" || fn == "vexw" || fn == "vexL" ||
                    fn == "vexpp") {
                    const uint64_t v = fn == "vexmap"
                                           ? static_cast<uint64_t>(xc.vexMap)
                                       : fn == "vexw"
                                           ? (xc.vexW ? 1 : 0)
                                       : fn == "vexL"
                                           ? (xc.vexL ? 1 : 0)
                                           : static_cast<uint64_t>(xc.vexPP);
                    if (t.kind != SpecCtor::Term::FIELD_EQ || v != t.value) {
                        ok = false;
                        break;
                    }
                    continue;
                }
                if (fn == "evex") {
                    if (!xc.evex) { ok = false; break; }
                    continue;
                }
                if (fn == "evexmap" || fn == "evexw" || fn == "evexL" ||
                    fn == "evexpp" || fn == "evexz" || fn == "evexb" ||
                    fn == "evexaaa") {
                    const uint64_t v = fn == "evexmap"
                                           ? static_cast<uint64_t>(xc.evexMap)
                                       : fn == "evexw"
                                           ? (xc.evexW ? 1 : 0)
                                       : fn == "evexL"
                                           ? static_cast<uint64_t>(xc.evexL)
                                       : fn == "evexpp"
                                           ? static_cast<uint64_t>(xc.evexPP)
                                       : fn == "evexz"
                                           ? (xc.evexZ ? 1 : 0)
                                       : fn == "evexb"
                                           ? (xc.evexB ? 1 : 0)
                                           : static_cast<uint64_t>(xc.evexAaa);
                    if (t.kind != SpecCtor::Term::FIELD_EQ || v != t.value) {
                        ok = false;
                        break;
                    }
                    continue;
                }
                if (fn == "pfxf2" || fn == "pfxf3" || fn == "pfx66" ||
                    fn == "pfxnone") {
                    const bool have = fn == "pfxf2" ? xc.opF2
                                    : fn == "pfxf3" ? xc.opF3
                                    : fn == "pfx66" ? xc.op66
                                                    : (!xc.opF2 && !xc.opF3 &&
                                                       !xc.op66);
                    if (!have) {
                        ok = false;
                        break;
                    }
                    if (t.kind == SpecCtor::Term::FIELD_EQ && t.value != 1) {
                        ok = false;
                        break;
                    }
                    continue;
                }
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
                    if (!decodeModrm(off)) {
                        ok = false; break;
                    }
                    continue;
                }
                // FIELD_EQ on register exports: /digit group check.
                // rreg=N and rmreg=N are FIXED encodings: REX.R/REX.B do NOT
                // extend them (e.g. 4f d1 03 = REX.WRXB rolq: reg field is
                // the /digit opcode extension, REX.R is ignored).
                if (t.kind == SpecCtor::Term::FIELD_EQ &&
                    (fn.rfind("rreg", 0) == 0 || fn.rfind("rmreg", 0) == 0 ||
                     fn.rfind("rq", 0) == 0)) {
                    if (fn.rfind("rmreg", 0) == 0 &&
                        (!xc.haveModrm || xc.mod != 3)) {
                        ok = false;
                        break;
                    }
                    int idx = fn.rfind("rmreg", 0) == 0 ? xc.rm : xc.reg;
                    if (fn.rfind("rq", 0) == 0)
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
                if (fn.rfind("rmmem", 0) == 0 &&
                    (!xc.haveModrm || xc.mod == 3)) {
                    ok = false;
                    break;
                }
                if ((fn == "rreg" || fn.rfind("rreg", 0) == 0 || fn == "ea") &&
                    !xc.haveModrm) {
                    ok = false;
                    break;
                }
                // FIELD_EQ on immediates: compare the encoded value
                if (t.kind == SpecCtor::Term::FIELD_EQ &&
                    (fn == "immb" || fn == "immw" || fn == "immd" ||
                     fn == "immq")) {
                    const int n = fn == "immb" ? 1
                                  : fn == "immw" ? 2
                                  : fn == "immd" ? 4 : 8;
                    uint64_t v = 0;
                    for (int i = 0; i < n; ++i)
                        v |= static_cast<uint64_t>(readByte(xc.cursor + i))
                             << (8 * i);
                    if (v != t.value) {
                        ok = false;
                        break;
                    }
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
            if (!f) {
                ok = false; break;
            }
            usedTok = std::max(usedTok, tokens_[f->token].size);
            const uint64_t v = fieldValue(*f);
            if (t.kind == SpecCtor::Term::FIELD_EQ) {
                if (v != t.value) {
                    if (std::getenv("SLEIGH_DBG"))
                        std::fprintf(stderr, "    %s: %s exp=%llu got=%llu (msb=%d lsb=%d)\n",
                                     c.name.c_str(), fn.c_str(),
                                     (unsigned long long)t.value,
                                     (unsigned long long)v,
                                     f->pieces.empty() ? -1 : f->pieces[0].msb,
                                     f->pieces.empty() ? -1 : f->pieces[0].lsb);
                    ok = false; break;
                }
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
        if (std::getenv("SLEIGH_DBG")) {
            std::fprintf(stderr, "  MISS %s @ %s\n", c.name.c_str(),
                         dbgFail ? dbgFail : "?");
        }
    }
    if (!matched) return false;

    out = PcodeInsn{};
    out.addr = addr;
    out.size = insnSize;
    out.nextAddr = addr + insnSize;
    nextId_ = 1;
    cache_->clear();

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
        } else if (size == 8) {
            static const char* r64[8] = {"rax", "rcx", "rdx", "rbx",
                                         "rsp", "rbp", "rsi", "rdi"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "r%d", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", r64[idx]);
        } else if (size == 16) {
            static const char* xmm[8] = {"xmm0", "xmm1", "xmm2", "xmm3",
                                         "xmm4", "xmm5", "xmm6", "xmm7"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "xmm%d", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", xmm[idx]);
        } else if (size == 32) {
            static const char* ymm[8] = {"ymm0", "ymm1", "ymm2", "ymm3",
                                         "ymm4", "ymm5", "ymm6", "ymm7"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "ymm%d", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", ymm[idx]);
        } else if (size == 64) {
            static const char* zmm[8] = {"zmm0", "zmm1", "zmm2", "zmm3",
                                         "zmm4", "zmm5", "zmm6", "zmm7"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "zmm%d", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", zmm[idx]);
        } else {
            static const char* r64[8] = {"rax", "rcx", "rdx", "rbx",
                                         "rsp", "rbp", "rsi", "rdi"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "r%d", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", r64[idx]);
        }
        uint64_t registerOffset = static_cast<uint64_t>(idx) * 8;
        // Without a REX prefix, byte register encodings 4..7 name the high
        // byte views AH/CH/DH/BH, not SPL/BPL/SIL/DIL.  Model those views as
        // byte 1 of the corresponding RAX/RCX/RDX/RBX storage register so
        // consumers can slice and writes can merge the correct bits.
        if (size == 1 && !xc.rex && idx >= 4 && idx < 8)
            registerOffset = static_cast<uint64_t>(idx - 4) * 8 + 1;
        Varnode* v = makeVarnode(out, Varnode::REGISTER,
                                 registerOffset, size, nm);
        return v->id;
    };
    auto addrText = [&]() -> std::string {
        std::string s = xc.segmentOverride == 4 ? "fs:["
                        : xc.segmentOverride == 5 ? "gs:[" : "[";
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
            std::snprintf(b, sizeof(b), "%s[0x%llx]",
                          xc.segmentOverride == 4 ? "fs:"
                          : xc.segmentOverride == 5 ? "gs:" : "",
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
        std::vector<uint64_t> parts;
        if (xc.segmentOverride == 4 || xc.segmentOverride == 5) {
            const uint64_t offset = xc.segmentOverride == 4
                                        ? X86_FS_BASE_OFFSET
                                        : X86_GS_BASE_OFFSET;
            Varnode* segment = makeVarnode(
                out, Varnode::REGISTER, offset, 8,
                xc.segmentOverride == 4 ? "fsbase" : "gsbase");
            parts.push_back(segment->id);
        }
        if (xc.ripRel) {
            parts.push_back(constVarnode(out, addr + insnSize + xc.disp, 8));
        } else {
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
        if (mname == "rregk") {
            Varnode* mask = makeVarnode(
                out, Varnode::REGISTER,
                8192 + static_cast<uint64_t>(xc.regReg) * 8, 8,
                "k" + std::to_string(xc.regReg));
            out.named[opname] = mask->id;
        } else if (mname == "rregmm" || mname == "rmregmm") {
            const int index = mname == "rregmm" ? xc.regReg : xc.rmReg;
            Varnode* mm = makeVarnode(
                out, Varnode::REGISTER,
                16384 + static_cast<uint64_t>(index) * 8, 8,
                "mm" + std::to_string(index));
            out.named[opname] = mm->id;
        } else if (mname == "rregv" || mname == "rmregv") {
            const int sz = xc.evex ? (xc.evexL == 2 ? 64
                                          : xc.evexL == 1 ? 32 : 16)
                                   : (xc.vexL ? 32 : 16);
            out.named[opname] = x86RegVarnode(mname == "rregv" ? xc.regReg
                                                               : xc.rmReg,
                                              sz);
        } else if (mname == "evexvvvv" || mname.rfind("evexvvvv", 0) == 0) {
            const int sz = mname.size() > 8 ? atoi(mname.c_str() + 8) / 8
                                            : (xc.evexL == 2 ? 64
                                               : xc.evexL == 1 ? 32 : 16);
            out.named[opname] = x86RegVarnode(xc.evexVvvv, sz);
        } else if (mname == "vexvvvv" || mname.rfind("vexvvvv", 0) == 0) {
            const int sz = mname.size() > 7 ? atoi(mname.c_str() + 7) / 8
                                            : (xc.vexL ? 32 : 16);
            out.named[opname] = x86RegVarnode(xc.vexVvvv, sz);
        } else if (mname == "acc" || mname.rfind("acc", 0) == 0) {
            // acc8/acc16/acc fixed-size, else rexw?8:opsz
            const int sz = mname.size() > 3 ? atoi(mname.c_str() + 3) / 8
                                            : (xc.rexw ? 8 : xc.opsz);
            out.named[opname] = x86RegVarnode(0, sz);
        } else if (mname == "sreg") {
            static const char* seg[8] = {"es", "cs", "ss", "ds", "fs", "gs", "?", "?"};
            Varnode* v = makeVarnode(out, Varnode::REGISTER,
                                     static_cast<uint64_t>(xc.regReg) * 8, 2,
                                     seg[xc.regReg & 7]);
            out.named[opname] = v->id;
        } else if (mname == "rreg" || mname.rfind("rreg", 0) == 0) {
            out.named[opname] = x86RegVarnode(xc.regReg, magicSize(mname));
        } else if (mname == "rmreg" || mname.rfind("rmreg", 0) == 0) {
            out.named[opname] = x86RegVarnode(xc.rmReg, magicSize(mname));
        } else if (mname == "rq" || mname.rfind("rq", 0) == 0) {
            const int idx = (readByte(0) & 7) | (xc.rexb ? 8 : 0);
            out.named[opname] = x86RegVarnode(idx, magicSize(mname));
        } else if (mname.rfind("rmmem", 0) == 0) {
            if (xc.evex && mname.size() > 5 && xc.mod == 1) {
                // EVEX compressed disp8: disp8 * N
                xc.disp *= atoi(mname.c_str() + 5);
            }
            const uint64_t ea = materializeAddr();
            auto it = out.varnodes.find(ea);
            if (it != out.varnodes.end()) it->second.name = addrText();
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

    // Integer x86 instructions share flag behavior across many encodings.
    // Emit that behavior centrally so register, immediate, and memory forms
    // cannot silently drift apart in the language specification.
    bool x86Handled = false;
    if (archX86_) {
        auto magicFor = [&](const std::string& operand) {
            for (auto it = magicExports.rbegin(); it != magicExports.rend(); ++it)
                if (it->first == operand) return it->second;
            return std::string();
        };
        auto isMemory = [&](const std::string& operand) {
            return magicFor(operand).rfind("rmmem", 0) == 0;
        };
        auto tmp = [&](int size, const std::string& name = std::string()) {
            return makeVarnode(out, Varnode::UNIQUE, nextId_++, size, name)->id;
        };
        auto emit1 = [&](POp op, uint64_t a, int size) {
            const uint64_t r = tmp(size);
            out.ops.push_back(PcodeOp{op, r, a, 0, 0});
            return r;
        };
        auto emit2 = [&](POp op, uint64_t a, uint64_t b, int size) {
            const uint64_t r = tmp(size);
            out.ops.push_back(PcodeOp{op, r, a, b, 0});
            return r;
        };
        auto emitSelect = [&](uint64_t c, uint64_t yes, uint64_t no, int size) {
            const uint64_t r = tmp(size);
            out.ops.push_back(PcodeOp{POp::SELECT, r, c, yes, no});
            return r;
        };
        auto resized = [&](uint64_t id, int size, bool signExtend) {
            const Varnode* v = out.find(id);
            if (v && v->size == size) return id;
            if (v && v->isConst()) {
                const int fromBits = std::max(1, v->size * 8);
                const uint64_t fromMask = fromBits >= 64
                                              ? ~0ULL
                                              : ((1ULL << fromBits) - 1);
                uint64_t value = v->offset & fromMask;
                if (signExtend && fromBits < size * 8) {
                    const uint64_t sign = 1ULL << (fromBits - 1);
                    value = (value ^ sign) - sign;
                }
                return constVarnode(out, value, size);
            }
            // Narrowing is truncation, not extension.  Emitting INT_ZEXT for
            // TEST AL,AL (whose decoded operand view may originate from RAX)
            // left the decompiler free to consume unspecified upper bits.
            if (v && v->size > size)
                return emit1(POp::SUBPIECE, id, size);
            return emit1(signExtend ? POp::INT_SEXT : POp::INT_ZEXT, id, size);
        };
        auto loadValue = [&](uint64_t address, int size) {
            const uint64_t r = tmp(size);
            out.ops.push_back(PcodeOp{POp::LOAD, r, address, 0, 0});
            return r;
        };
        auto applyEvexMask = [&](uint64_t computed, uint64_t previous,
                                 int size, int laneBits) {
            if (!xc.evex || xc.evexAaa == 0) return computed;
            Varnode* mask = makeVarnode(
                out, Varnode::REGISTER,
                8192 + static_cast<uint64_t>(xc.evexAaa) * 8, 8,
                "k" + std::to_string(xc.evexAaa));
            const uint64_t result = tmp(size);
            const uint16_t aux = static_cast<uint16_t>(
                laneBits | (xc.evexZ ? 0x8000 : 0));
            out.ops.push_back(PcodeOp{POp::SIMD_MASK, result, computed,
                                      previous, mask->id, aux});
            return result;
        };
        auto applyEvexStoreMask = [&](uint64_t computed, uint64_t previous,
                                      int size, int laneBits) {
            if (!xc.evex || xc.evexAaa == 0) return computed;
            Varnode* mask = makeVarnode(
                out, Varnode::REGISTER,
                8192 + static_cast<uint64_t>(xc.evexAaa) * 8, 8,
                "k" + std::to_string(xc.evexAaa));
            const uint64_t result = tmp(size);
            out.ops.push_back(PcodeOp{
                POp::SIMD_MASK, result, computed, previous, mask->id,
                static_cast<uint16_t>(laneBits)});
            return result;
        };
        auto flag = [&](const char* name) {
            const SpecRegister* r = findReg(name);
            return r ? regVarnode(out, *r) : uint64_t{0};
        };
        auto writeFlag = [&](const char* name, uint64_t value) {
            if (const uint64_t dst = flag(name))
                out.ops.push_back(PcodeOp{POp::COPY, dst, value, 0, 0});
        };
        auto bitFlag = [&](uint64_t value, int bit, int valueSize) {
            const uint64_t shift = constVarnode(out, static_cast<uint64_t>(bit), valueSize);
            const uint64_t shifted = emit2(POp::INT_RIGHT, value, shift, valueSize);
            return emit2(POp::INT_AND, shifted, constVarnode(out, 1, valueSize), 1);
        };
        auto auxFlag = [&](uint64_t a, uint64_t b, uint64_t result, int size) {
            const uint64_t x = emit2(POp::INT_XOR, a, b, size);
            const uint64_t y = emit2(POp::INT_XOR, x, result, size);
            const uint64_t m = emit2(POp::INT_AND, y, constVarnode(out, 0x10, size), size);
            return emit2(POp::INT_NOTEQUAL, m, constVarnode(out, 0, size), 1);
        };
        auto commonFlags = [&](uint64_t a, uint64_t b, uint64_t result,
                               int size, POp overflowOp) {
            writeFlag("PF", emit1(POp::INT_PARITY, result, 1));
            writeFlag("AF", auxFlag(a, b, result, size));
            writeFlag("ZF", emit2(POp::INT_EQUAL, result,
                                    constVarnode(out, 0, size), 1));
            writeFlag("SF", bitFlag(result, size * 8 - 1, size));
            writeFlag("OF", emit2(overflowOp, a, b, 1));
        };
        auto byteOpcode = [&](uint8_t op) {
            switch (op) {
            case 0x00: case 0x02: case 0x04: case 0x08: case 0x0A: case 0x0C:
            case 0x10: case 0x12: case 0x18: case 0x1A: case 0x20: case 0x22:
            case 0x24: case 0x28: case 0x2A: case 0x2C: case 0x30: case 0x32:
            case 0x34: case 0x38: case 0x3A: case 0x3C: case 0x80: case 0x84:
            case 0xA8: case 0xC0: case 0xD0: case 0xD2: case 0xF6: case 0xFE:
                return true;
            default: return false;
            }
        };
        auto condition = [&](const std::string& cc) {
            const uint64_t zero = constVarnode(out, 0, 1);
            auto eq0 = [&](const char* n) {
                return emit2(POp::INT_EQUAL, flag(n), zero, 1);
            };
            auto ne0 = [&](const char* n) {
                return emit2(POp::INT_NOTEQUAL, flag(n), zero, 1);
            };
            if (cc == "o") return ne0("OF");
            if (cc == "no") return eq0("OF");
            if (cc == "b") return ne0("CF");
            if (cc == "ae") return eq0("CF");
            if (cc == "e") return ne0("ZF");
            if (cc == "ne") return eq0("ZF");
            if (cc == "be") return emit2(POp::INT_OR, ne0("CF"), ne0("ZF"), 1);
            if (cc == "a") return emit2(POp::INT_AND, eq0("CF"), eq0("ZF"), 1);
            if (cc == "s") return ne0("SF");
            if (cc == "ns") return eq0("SF");
            if (cc == "p") return ne0("PF");
            if (cc == "np") return eq0("PF");
            if (cc == "l") return emit2(POp::INT_NOTEQUAL, flag("SF"), flag("OF"), 1);
            if (cc == "ge") return emit2(POp::INT_EQUAL, flag("SF"), flag("OF"), 1);
            if (cc == "le")
                return emit2(POp::INT_OR, ne0("ZF"),
                             emit2(POp::INT_NOTEQUAL, flag("SF"), flag("OF"), 1), 1);
            if (cc == "g")
                return emit2(POp::INT_AND, eq0("ZF"),
                             emit2(POp::INT_EQUAL, flag("SF"), flag("OF"), 1), 1);
            return zero;
        };

        const std::string& name = matched->name;
        if (name == "push" && out.named.count("src")) {
            // Keep ordinary stack transfers as first-class LOAD/STORE p-code.
            // The x86 specification intentionally does not declare the GPR
            // bank, so evaluating the textual `sp = sp - 8` constructor would
            // otherwise fold an unknown `sp` to zero.  Explicit p-code also
            // lets SSA, stack-slot recovery, and the C emitter follow saved
            // non-volatile registers without an opaque system operation.
            const unsigned width = xc.opsz == 2 ? 2U : 8U;
            const uint64_t stack = x86RegVarnode(4, 8);
            const uint64_t sourceId = out.named["src"];
            const uint64_t value = isMemory("src")
                                       ? loadValue(sourceId, width)
                                       : resized(sourceId, width, true);
            const uint64_t nextStack = emit2(
                POp::INT_SUB, stack, constVarnode(out, width, 8), 8);
            out.ops.push_back(PcodeOp{POp::STORE, 0, nextStack, 0, value});
            out.ops.push_back(PcodeOp{POp::COPY, stack, nextStack, 0, 0});
            x86Handled = true;
        } else if (name == "int3" || name == "int1" || name == "int" ||
            name == "ud0" || name == "ud2" || name == "udb") {
            const uint64_t vector = constVarnode(
                out, (name == "int3") ? 3 : (name == "int1") ? 1 :
                     (name == "int")
                         ? out.find(out.named.count("imm") ? out.named["imm"] :
                                    out.named.count("n") ? out.named["n"] : 0)
                               ? out.find(out.named.count("imm") ? out.named["imm"] :
                                          out.named["n"])->offset : 0
                         : 6, 1);
            out.ops.push_back(PcodeOp{POp::X86_SYSTEM, 0, vector, 0, 0,
                static_cast<uint16_t>(X86SystemAction::SoftwareInterrupt)});
            x86Handled = true;
        } else if (name == "syscall") {
            out.ops.push_back(PcodeOp{POp::X86_SYSTEM, 0, 0, 0, 0,
                static_cast<uint16_t>(X86SystemAction::FastSystemCall)});
            x86Handled = true;
        } else if (name == "lfence" || name == "sfence" ||
                   name == "mfence" || name == "wait") {
            const uint16_t kind = name == "lfence" ? 1
                                  : name == "sfence" ? 2
                                  : name == "mfence" ? 3 : 4;
            out.ops.push_back(PcodeOp{POp::MEMORY_BARRIER, 0, 0, 0, 0, kind});
            x86Handled = true;
        } else if (name == "nop" || name == "pause" || name.rfind("prefetch", 0) == 0 ||
                   name == "clflush" || name == "clflushopt" ||
                   name == "clwb") {
            const uint64_t address = out.named.count("dst")
                                         ? out.named["dst"] : 0;
            out.ops.push_back(PcodeOp{POp::CACHE_HINT, 0, address, 0, 0});
            x86Handled = true;
        } else if ((name == "fxsave" || name == "xsave" ||
                    name == "xsavec" || name == "xsaves") &&
                   out.named.count("dst")) {
            const uint16_t format = name == "fxsave" ? 0
                                    : name == "xsave" ? 1
                                    : name == "xsavec" ? 2 : 3;
            out.ops.push_back(PcodeOp{POp::X86_XSTATE_SAVE, 0,
                                      out.named["dst"], 0, 0, format});
            x86Handled = true;
        } else if ((name == "fxrstor" || name == "xrstor" ||
                    name == "xrstors") && out.named.count("dst")) {
            const uint16_t format = name == "fxrstor" ? 0
                                    : name == "xrstor" ? 1 : 3;
            out.ops.push_back(PcodeOp{POp::X86_XSTATE_RESTORE, 0,
                                      out.named["dst"], 0, 0, format});
            x86Handled = true;
        } else {
            X86SystemAction action = X86SystemAction::None;
            if (name == "cpuid") action = X86SystemAction::Cpuid;
            else if (name == "rdmsr") action = X86SystemAction::ReadMsr;
            else if (name == "wrmsr") action = X86SystemAction::WriteMsr;
            else if (name == "xgetbv") action = X86SystemAction::GetXbv;
            else if (name == "xsetbv") action = X86SystemAction::SetXbv;
            else if (name == "clts") action = X86SystemAction::ClearTaskSwitched;
            else if (name == "swapgs") action = X86SystemAction::SwapGs;
            else if (name == "cli") action = X86SystemAction::DisableInterrupts;
            else if (name == "sti") action = X86SystemAction::EnableInterrupts;
            else if (name == "hlt") action = X86SystemAction::Halt;
            else if (name == "invlpg") action = X86SystemAction::InvalidatePage;
            else if (name == "invd") action = X86SystemAction::InvalidateCaches;
            else if (name == "wbinvd")
                action = X86SystemAction::WriteBackInvalidateCaches;
            else if (name == "sgdt") action = X86SystemAction::StoreGdtr;
            else if (name == "sidt") action = X86SystemAction::StoreIdtr;
            else if (name == "lgdt") action = X86SystemAction::LoadGdtr;
            else if (name == "lidt") action = X86SystemAction::LoadIdtr;
            else if (name == "sldt") action = X86SystemAction::StoreLdt;
            else if (name == "lldt") action = X86SystemAction::LoadLdt;
            else if (name == "str") action = X86SystemAction::StoreTask;
            else if (name == "ltr") action = X86SystemAction::LoadTask;
            else if (name == "movcr")
                action = readByte(1) == 0x20 ? X86SystemAction::ReadControl
                                             : X86SystemAction::WriteControl;
            else if (name == "in" || name == "out") {
                const uint8_t opcode = readByte(0);
                action = (opcode == 0xE4 || opcode == 0xE5 ||
                          opcode == 0xEC || opcode == 0xED)
                             ? X86SystemAction::PortIn
                             : X86SystemAction::PortOut;
            }
            if (action != X86SystemAction::None) {
                uint64_t operand = out.named.count("dst") ? out.named["dst"] : 0;
                const bool selectorLoad = action == X86SystemAction::LoadLdt ||
                                          action == X86SystemAction::LoadTask;
                const bool selectorStore = action == X86SystemAction::StoreLdt ||
                                           action == X86SystemAction::StoreTask;
                if (selectorLoad && out.named.count("dst") && isMemory("dst"))
                    operand = loadValue(operand, 2);
                uint64_t output = action == X86SystemAction::ReadControl ||
                                  (selectorStore && !isMemory("dst"))
                                      ? operand : 0;
                uint64_t memoryResult = 0;
                if (selectorStore && out.named.count("dst") && isMemory("dst")) {
                    memoryResult = tmp(2);
                    output = memoryResult;
                }
                uint16_t aux = static_cast<uint16_t>(action);
                if (name == "movcr") aux |= static_cast<uint16_t>(xc.reg << 8);
                if (action == X86SystemAction::PortIn ||
                    action == X86SystemAction::PortOut) {
                    const uint8_t opcode = readByte(0);
                    const int width = (opcode == 0xE4 || opcode == 0xE6 ||
                                       opcode == 0xEC || opcode == 0xEE)
                                          ? 1 : std::min(xc.opsz, 4);
                    operand = out.named.count("imm")
                                  ? out.named["imm"] : x86RegVarnode(2, 2);
                    const uint64_t accumulator = out.named.count("acc")
                                                     ? out.named["acc"]
                                                     : x86RegVarnode(0, width);
                    output = action == X86SystemAction::PortIn
                                 ? accumulator : 0;
                    aux |= static_cast<uint16_t>(width << 8);
                    out.ops.push_back(PcodeOp{POp::X86_SYSTEM, output,
                                              operand, accumulator, 0, aux});
                    x86Handled = true;
                } else {
                    out.ops.push_back(PcodeOp{POp::X86_SYSTEM, output,
                                              operand, 0, 0, aux});
                    if (memoryResult)
                        out.ops.push_back(PcodeOp{POp::STORE, 0,
                                                  out.named["dst"], 0,
                                                  memoryResult});
                    x86Handled = true;
                }
            }
        }
        if (!x86Handled) {
            X86SystemAction action = X86SystemAction::None;
            uint64_t output = 0, input0 = 0, input1 = 0;
            unsigned selector = 0;
            if (name == "cwd" || name == "cdq" || name == "cqo") {
                action = X86SystemAction::SignExtendHigh;
                selector = name == "cwd" ? 2 : name == "cdq" ? 4 : 8;
            } else if ((name == "mul" || name == "imul") &&
                       !out.named.count("dst") && out.named.count("src")) {
                const unsigned width = readByte(0) == 0xF6 ? 1 : xc.opsz;
                const bool signedMultiply = name == "imul";
                input0 = isMemory("src")
                    ? loadValue(out.named["src"], width)
                    : resized(out.named["src"], width, false);
                if (width == 1) {
                    // The byte form writes AX as AL:AH; keep the dedicated
                    // architectural action for this overlapping-register case.
                    action = X86SystemAction::MultiplyAccumulator;
                    selector = static_cast<unsigned>(
                        width | (signedMultiply ? 0x80 : 0));
                } else {
                    const uint64_t accumulator = x86RegVarnode(0, width);
                    const uint64_t highRegister = x86RegVarnode(2, width);
                    const uint64_t left = resized(accumulator, width, false);
                    const uint64_t right = resized(input0, width, false);
                    uint64_t low = 0, high = 0;
                    if (width < 8) {
                        const int wide = static_cast<int>(width * 2);
                        const uint64_t wideLeft = resized(
                            left, wide, signedMultiply);
                        const uint64_t wideRight = resized(
                            right, wide, signedMultiply);
                        const uint64_t product = emit2(
                            POp::INT_MULT, wideLeft, wideRight, wide);
                        low = resized(product, static_cast<int>(width), false);
                        const uint64_t shifted = emit2(
                            POp::INT_RIGHT, product,
                            constVarnode(out, width * 8, wide), wide);
                        high = resized(shifted, static_cast<int>(width), false);
                    } else {
                        // Portable 64x64 -> 128 multiplication using four
                        // 32-bit partial products.  This lowers to ordinary
                        // p-code so decompilation preserves RDX:RAX instead
                        // of silently dropping the system action.
                        const uint64_t mask32 = constVarnode(
                            out, 0xffffffffULL, 8);
                        const uint64_t shift32 = constVarnode(out, 32, 8);
                        const uint64_t leftLow = emit2(
                            POp::INT_AND, left, mask32, 8);
                        const uint64_t leftHigh = emit2(
                            POp::INT_RIGHT, left, shift32, 8);
                        const uint64_t rightLow = emit2(
                            POp::INT_AND, right, mask32, 8);
                        const uint64_t rightHigh = emit2(
                            POp::INT_RIGHT, right, shift32, 8);
                        const uint64_t first = emit2(
                            POp::INT_MULT, leftLow, rightLow, 8);
                        const uint64_t bottom = emit2(
                            POp::INT_AND, first, mask32, 8);
                        const uint64_t firstHigh = emit2(
                            POp::INT_RIGHT, first, shift32, 8);
                        const uint64_t second = emit2(
                            POp::INT_ADD,
                            emit2(POp::INT_MULT, leftHigh, rightLow, 8),
                            firstHigh, 8);
                        const uint64_t middle = emit2(
                            POp::INT_AND, second, mask32, 8);
                        const uint64_t carry = emit2(
                            POp::INT_RIGHT, second, shift32, 8);
                        const uint64_t third = emit2(
                            POp::INT_ADD,
                            emit2(POp::INT_MULT, leftLow, rightHigh, 8),
                            middle, 8);
                        low = emit2(
                            POp::INT_OR,
                            emit2(POp::INT_LEFT, third, shift32, 8),
                            bottom, 8);
                        high = emit2(
                            POp::INT_ADD,
                            emit2(POp::INT_ADD,
                                  emit2(POp::INT_MULT, leftHigh, rightHigh, 8),
                                  carry, 8),
                            emit2(POp::INT_RIGHT, third, shift32, 8), 8);
                        if (signedMultiply) {
                            const uint64_t leftSign = bitFlag(left, 63, 8);
                            const uint64_t rightSign = bitFlag(right, 63, 8);
                            high = emit2(
                                POp::INT_SUB, high,
                                emit2(POp::INT_MULT, leftSign, right, 8), 8);
                            high = emit2(
                                POp::INT_SUB, high,
                                emit2(POp::INT_MULT, rightSign, left, 8), 8);
                        }
                    }
                    const uint64_t zero = constVarnode(out, 0, width);
                    uint64_t overflow = emit2(
                        POp::INT_NOTEQUAL, high, zero, 1);
                    if (signedMultiply) {
                        const uint64_t sign = bitFlag(
                            low, static_cast<int>(width * 8 - 1), width);
                        const uint64_t expected = emitSelect(
                            sign, constVarnode(out,
                                width == 8 ? ~0ULL
                                           : ((1ULL << (width * 8)) - 1),
                                width), zero, width);
                        overflow = emit2(
                            POp::INT_NOTEQUAL, high, expected, 1);
                    }
                    out.ops.push_back(PcodeOp{
                        POp::COPY, accumulator, low, 0, 0});
                    out.ops.push_back(PcodeOp{
                        POp::COPY, highRegister, high, 0, 0});
                    writeFlag("CF", overflow);
                    writeFlag("OF", overflow);
                    x86Handled = true;
                }
            } else if ((name == "cmpxchg8b" || name == "cmpxchg16b") &&
                       out.named.count("dst")) {
                action = X86SystemAction::CompareExchangeWide;
                selector = name == "cmpxchg16b" ? 16 : 8;
                input0 = out.named["dst"];
            } else if (name == "enter") {
                action = X86SystemAction::EnterFrame;
                input0 = constVarnode(out,
                    static_cast<uint64_t>(readByte(1)) |
                    (static_cast<uint64_t>(readByte(2)) << 8), 2);
                input1 = constVarnode(out, readByte(3), 1);
            } else if (name == "pop" && out.named.count("dst")) {
                selector = xc.opsz == 2 ? 2 : 8;
                const bool memory = isMemory("dst");
                const uint64_t stack = x86RegVarnode(4, 8);
                output = loadValue(stack, selector);
                const uint64_t nextStack = emit2(
                    POp::INT_ADD, stack, constVarnode(out, selector, 8), 8);
                out.ops.push_back(PcodeOp{POp::COPY, stack, nextStack, 0, 0});
                if (memory)
                    out.ops.push_back(PcodeOp{POp::STORE, 0, out.named["dst"], 0, output});
                else
                    out.ops.push_back(PcodeOp{POp::COPY, out.named["dst"],
                                              output, 0, 0});
                x86Handled = true;
            } else if (name == "pushf" || name == "popf") {
                action = name == "pushf" ? X86SystemAction::PushFlags
                                          : X86SystemAction::PopFlags;
                selector = xc.opsz == 2 ? 2 : 8;
            } else if (name == "lahf") action = X86SystemAction::LoadAhFlags;
            else if (name == "sahf") action = X86SystemAction::StoreAhFlags;
            else if (name == "salc") action = X86SystemAction::SetAlCarry;
            else if (name == "ldmxcsr" || name == "stmxcsr") {
                action = name == "ldmxcsr" ? X86SystemAction::LoadMxcsr
                                            : X86SystemAction::StoreMxcsr;
                input0 = out.named.count("dst") ? out.named["dst"] : 0;
            } else if (name == "insb" || name == "insd" || name == "insq" ||
                       name == "outsb" || name == "outsd" || name == "outsq") {
                action = name.rfind("ins", 0) == 0
                    ? X86SystemAction::StringPortIn
                    : X86SystemAction::StringPortOut;
                selector = name.back() == 'b' ? 1 : name.back() == 'd' ? 4 : 8;
            } else if (name == "rdtsc") action = X86SystemAction::ReadTimestamp;
            else if (name == "rdtscp") action = X86SystemAction::ReadTimestampAux;
            else if (name == "rdpmc") action = X86SystemAction::ReadPerformanceCounter;
            else if (name == "rdrand" || name == "rdseed") {
                action = X86SystemAction::RandomValue;
                if (out.named.count("dst")) {
                    output = out.named["dst"];
                    const Varnode* node = out.find(output);
                    selector = node ? node->size : xc.opsz;
                }
            } else if (name == "rdpid") {
                action = X86SystemAction::ReadProcessorId;
                output = out.named.count("dst") ? out.named["dst"] : 0;
            } else if (name == "rdsspd" || name == "rdsspq") {
                action = X86SystemAction::ReadShadowStack;
                output = out.named.count("dst") ? out.named["dst"] : 0;
            } else if (name == "monitor" || name == "monitorx")
                action = X86SystemAction::ArmMonitor;
            else if (name == "mwait" || name == "mwaitx")
                action = X86SystemAction::MonitorWait;
            else if (name == "clac" || name == "stac") {
                action = X86SystemAction::SetAccessControl;
                selector = name == "stac" ? 1 : 0;
            } else if (name == "sysret") action = X86SystemAction::FastSystemReturn;
            else if (name == "iret") action = X86SystemAction::InterruptReturn;
            else if (name == "lret") {
                action = X86SystemAction::FarReturn;
                if (out.named.count("imm")) {
                    const Varnode* immediate = out.find(out.named["imm"]);
                    selector = immediate ? static_cast<unsigned>(immediate->offset) : 0;
                }
            } else if (name == "lar" || name == "lsl") {
                action = name == "lar" ? X86SystemAction::AccessRights
                                        : X86SystemAction::SegmentLimit;
                if (out.named.count("src"))
                    input0 = isMemory("src") ? loadValue(out.named["src"], 2)
                                              : resized(out.named["src"], 2, false);
                output = out.named.count("dst") ? out.named["dst"] : 0;
            } else if (name == "xlat") action = X86SystemAction::TranslateByte;

            if (!x86Handled && action != X86SystemAction::None) {
                out.ops.push_back(PcodeOp{POp::X86_SYSTEM, output,
                    input0, input1, 0,
                    static_cast<uint16_t>(static_cast<uint16_t>(action) |
                                          static_cast<uint16_t>(selector << 8))});
                x86Handled = true;
            }
        }

        const std::set<std::string> arithmetic = {
            "add", "adc", "sub", "sbb", "cmp", "and", "or", "xor",
            "test", "inc", "dec", "neg", "xadd"
        };
        if (!x86Handled && (name == "cld" || name == "std")) {
            out.ops.push_back(PcodeOp{
                POp::COPY, flag("DF"),
                constVarnode(out, name == "std" ? 1 : 0, 1), 0, 0});
            x86Handled = true;
        }

        if (!x86Handled) {
            const uint8_t opcode = readByte(0);
            unsigned stringOperation = 0;
            if (opcode == 0xA4 || opcode == 0xA5) stringOperation = 1;
            else if (opcode == 0xA6 || opcode == 0xA7) stringOperation = 2;
            else if (opcode == 0xAA || opcode == 0xAB) stringOperation = 3;
            else if (opcode == 0xAC || opcode == 0xAD) stringOperation = 4;
            else if (opcode == 0xAE || opcode == 0xAF) stringOperation = 5;
            if (stringOperation) {
                const unsigned width = (opcode & 1U) == 0
                                           ? 1U : static_cast<unsigned>(xc.opsz);
                const unsigned repeat = name == "rep" ? 1U
                                          : name == "repe" ? 2U
                                          : name == "repne" ? 3U : 0U;
                out.ops.push_back(PcodeOp{
                    POp::X86_STRING, 0, 0, 0, 0,
                    static_cast<uint16_t>(stringOperation | (width << 4) |
                                          (repeat << 8))});
                x86Handled = true;
            }
        }

        if (arithmetic.count(name) && out.named.count("dst")) {
            const uint8_t opcodeByte = readByte(0);
            const bool dstMem = isMemory("dst");
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = (byteOpcode(opcodeByte) ||
                              (name == "xadd" && readByte(1) == 0xC0))
                                 ? 1
                                 : (dstMem ? xc.opsz
                                           : (dstNode && dstNode->size
                                                  ? dstNode->size : xc.opsz));
            uint64_t a = dstMem ? loadValue(dstId, size)
                                : resized(dstId, size, false);
            if (name == "xadd") {
                const uint64_t snapshot = tmp(size);
                out.ops.push_back(PcodeOp{POp::COPY, snapshot, a, 0, 0});
                a = snapshot;
            }
            uint64_t b = constVarnode(out, 1, size);
            std::string rhsName;
            if (out.named.count("src")) rhsName = "src";
            else if (out.named.count("imm")) rhsName = "imm";
            if (!rhsName.empty()) {
                const uint64_t rhsId = out.named[rhsName];
                b = isMemory(rhsName) ? loadValue(rhsId, size)
                                      : resized(rhsId, size, rhsName == "imm");
            }

            uint64_t result = 0;
            if (name == "and" || name == "or" || name == "xor" || name == "test") {
                const POp op = name == "and" || name == "test" ? POp::INT_AND
                               : name == "or" ? POp::INT_OR : POp::INT_XOR;
                result = emit2(op, a, b, size);
                const uint64_t zero = constVarnode(out, 0, 1);
                writeFlag("CF", zero);
                writeFlag("OF", zero);
                writeFlag("AF", zero); // architecturally undefined; deterministic IR
                writeFlag("PF", emit1(POp::INT_PARITY, result, 1));
                writeFlag("ZF", emit2(POp::INT_EQUAL, result,
                                       constVarnode(out, 0, size), 1));
                writeFlag("SF", bitFlag(result, size * 8 - 1, size));
            } else if (name == "add" || name == "xadd") {
                result = emit2(POp::INT_ADD, a, b, size);
                writeFlag("CF", emit2(POp::INT_CARRY, a, b, 1));
                commonFlags(a, b, result, size, POp::INT_SCARRY);
            } else if (name == "sub" || name == "cmp") {
                result = emit2(POp::INT_SUB, a, b, size);
                writeFlag("CF", emit2(POp::INT_LESS, a, b, 1));
                commonFlags(a, b, result, size, POp::INT_SBORROW);
            } else if (name == "inc" || name == "dec") {
                const bool isInc = name == "inc";
                result = emit2(isInc ? POp::INT_ADD : POp::INT_SUB, a, b, size);
                commonFlags(a, b, result, size,
                            isInc ? POp::INT_SCARRY : POp::INT_SBORROW);
            } else if (name == "neg") {
                const uint64_t zero = constVarnode(out, 0, size);
                result = emit2(POp::INT_SUB, zero, a, size);
                writeFlag("CF", emit2(POp::INT_NOTEQUAL, a, zero, 1));
                commonFlags(zero, a, result, size, POp::INT_SBORROW);
            } else if (name == "adc" || name == "sbb") {
                const uint64_t cin1 = tmp(1);
                out.ops.push_back(PcodeOp{POp::COPY, cin1, flag("CF"), 0, 0});
                const uint64_t cin = resized(cin1, size, false);
                const bool add = name == "adc";
                const uint64_t first = emit2(add ? POp::INT_ADD : POp::INT_SUB,
                                             a, b, size);
                result = emit2(add ? POp::INT_ADD : POp::INT_SUB,
                               first, cin, size);
                const uint64_t c0 = emit2(add ? POp::INT_CARRY : POp::INT_LESS,
                                          a, b, 1);
                const uint64_t c1 = emit2(add ? POp::INT_CARRY : POp::INT_LESS,
                                          first, cin, 1);
                writeFlag("CF", emit2(POp::INT_OR, c0, c1, 1));
                const POp signedOverflow = add ? POp::INT_SCARRY
                                               : POp::INT_SBORROW;
                const uint64_t o0 = emit2(signedOverflow, a, b, 1);
                const uint64_t o1 = emit2(signedOverflow, first, cin, 1);
                // The two one-bit additions/subtractions cannot overflow in
                // the same direction simultaneously.  XOR therefore gives
                // the exact overflow of a +/- b +/- carry-in, including the
                // INT_MAX+CF and INT_MIN-1 cancellation boundaries.
                const uint64_t overflow = emit2(POp::INT_XOR, o0, o1, 1);
                commonFlags(a, b, result, size, signedOverflow);
                writeFlag("OF", overflow);
            }

            if (name != "cmp" && name != "test") {
                if (dstMem)
                    out.ops.push_back(PcodeOp{POp::STORE, 0, dstId, 0, result});
                else
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                if (name == "xadd" && out.named.count("src"))
                    out.ops.push_back(PcodeOp{POp::COPY, out.named["src"], a, 0, 0});
            }
            x86Handled = result != 0;
        }

        if (!x86Handled && name == "bswap" && out.named.count("dst")) {
            const int size = xc.rexw ? 8 : 4;
            const int index = (readByte(1) - 0xc8) | (xc.rexb ? 8 : 0);
            const uint64_t destination = x86RegVarnode(index, size);
            const uint64_t result = tmp(size);
            out.ops.push_back(PcodeOp{POp::INT_BSWAP, result,
                                      destination, 0, 0});
            out.ops.push_back(PcodeOp{POp::COPY, destination, result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && name == "crc32" && out.named.count("dst") &&
            out.named.count("src")) {
            const int width = readByte(2) == 0xF0 ? 1 : xc.opsz;
            const uint64_t source = isMemory("src")
                                        ? loadValue(out.named["src"], width)
                                        : resized(out.named["src"], width, false);
            const uint64_t result = tmp(4);
            out.ops.push_back(PcodeOp{POp::INT_CRC32C, result,
                                      out.named["dst"], source, 0,
                                      static_cast<uint16_t>(width)});
            out.ops.push_back(PcodeOp{POp::COPY, out.named["dst"],
                                      result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && (name == "idiv" || name == "div") &&
            out.named.count("src")) {
            const int width = readByte(0) == 0xF6 ? 1 : xc.opsz;
            const uint64_t divisor = isMemory("src")
                                         ? loadValue(out.named["src"], width)
                                         : resized(out.named["src"], width, false);
            out.ops.push_back(PcodeOp{POp::X86_DIVIDE, 0, divisor, 0, 0,
                                      static_cast<uint16_t>(width |
                                          (name == "div" ? 0x0100 : 0))});
            x86Handled = true;
        }

        if (!x86Handled && name == "imul" && out.named.count("dst") &&
            out.named.count("src")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size ? dstNode->size : xc.opsz;
            const uint64_t srcId = out.named["src"];
            uint64_t a = out.named.count("imm")
                             ? (isMemory("src") ? loadValue(srcId, size)
                                                : resized(srcId, size, false))
                             : resized(dstId, size, false);
            uint64_t b = out.named.count("imm")
                             ? resized(out.named["imm"], size, true)
                             : (isMemory("src") ? loadValue(srcId, size)
                                                : resized(srcId, size, false));
            const uint64_t result = emit2(POp::INT_MULT, a, b, size);
            const uint64_t overflow = emit2(POp::INT_SMULT_OVERFLOW, a, b, 1);
            writeFlag("CF", overflow); writeFlag("OF", overflow);
            out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && name == "cmpxchg" && out.named.count("dst") &&
            out.named.count("src")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const bool dstMem = isMemory("dst");
            const int size = readByte(1) == 0xB0 ? 1
                                 : (dstMem ? xc.opsz
                                           : (dstNode ? dstNode->size : xc.opsz));
            const uint64_t oldDst = dstMem ? loadValue(dstId, size)
                                           : resized(dstId, size, false);
            const uint64_t src = resized(out.named["src"], size, false);
            const uint64_t accumulator = x86RegVarnode(0, size);
            const uint64_t oldAcc = resized(accumulator, size, false);
            const uint64_t difference = emit2(POp::INT_SUB, oldAcc, oldDst, size);
            writeFlag("CF", emit2(POp::INT_LESS, oldAcc, oldDst, 1));
            commonFlags(oldAcc, oldDst, difference, size, POp::INT_SBORROW);
            const uint64_t equal = emit2(POp::INT_EQUAL, oldAcc, oldDst, 1);
            const uint64_t newDst = emitSelect(equal, src, oldDst, size);
            const uint64_t newAcc = emitSelect(equal, oldAcc, oldDst, size);
            if (dstMem)
                out.ops.push_back(PcodeOp{POp::STORE, 0, dstId, 0, newDst});
            else
                out.ops.push_back(PcodeOp{POp::COPY, dstId, newDst, 0, 0});
            out.ops.push_back(PcodeOp{POp::COPY, accumulator, newAcc, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && (name == "shl" || name == "sal" ||
                            name == "shr" || name == "sar") &&
            out.named.count("dst")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const bool dstMem = isMemory("dst");
            const int size = byteOpcode(readByte(0))
                                 ? 1
                                 : (dstMem ? xc.opsz
                                           : (dstNode ? dstNode->size : xc.opsz));
            const uint64_t a = dstMem ? loadValue(dstId, size)
                                      : resized(dstId, size, false);
            uint64_t count = constVarnode(out, 1, size);
            if (out.named.count("imm"))
                count = resized(out.named["imm"], size, false);
            else if (readByte(0) == 0xD2 || readByte(0) == 0xD3)
                count = resized(x86RegVarnode(1, 1), size, false);
            const uint64_t mask = constVarnode(out, size == 8 ? 0x3f : 0x1f, size);
            count = emit2(POp::INT_AND, count, mask, size);
            const POp shiftOp = (name == "shl" || name == "sal") ? POp::INT_LEFT
                                : name == "shr" ? POp::INT_RIGHT
                                                : POp::INT_SRIGHT;
            const uint64_t result = emit2(shiftOp, a, count, size);
            const uint64_t one = constVarnode(out, 1, size);
            const uint64_t nonzero = emit2(POp::INT_NOTEQUAL, count,
                                           constVarnode(out, 0, size), 1);
            uint64_t cfCandidate = 0;
            if (name == "shl" || name == "sal") {
                const uint64_t fromTop = emit2(POp::INT_SUB,
                                               constVarnode(out, size * 8, size),
                                               count, size);
                cfCandidate = emit2(POp::INT_AND,
                                    emit2(POp::INT_RIGHT, a, fromTop, size), one, 1);
            } else {
                const uint64_t pos = emit2(POp::INT_SUB, count, one, size);
                cfCandidate = emit2(POp::INT_AND,
                                    emit2(POp::INT_RIGHT, a, pos, size), one, 1);
            }
            const uint64_t oldCF = flag("CF"), oldOF = flag("OF");
            writeFlag("CF", emitSelect(nonzero, cfCandidate, oldCF, 1));
            const uint64_t isOne = emit2(POp::INT_EQUAL, count, one, 1);
            uint64_t ofCandidate = constVarnode(out, 0, 1);
            if (name == "shl" || name == "sal")
                ofCandidate = emit2(POp::INT_XOR,
                                    bitFlag(result, size * 8 - 1, size), cfCandidate, 1);
            else if (name == "shr")
                ofCandidate = bitFlag(a, size * 8 - 1, size);
            writeFlag("OF", emitSelect(isOne, ofCandidate, oldOF, 1));
            writeFlag("PF", emitSelect(nonzero, emit1(POp::INT_PARITY, result, 1),
                                        flag("PF"), 1));
            writeFlag("ZF", emitSelect(nonzero,
                                        emit2(POp::INT_EQUAL, result,
                                              constVarnode(out, 0, size), 1),
                                        flag("ZF"), 1));
            writeFlag("SF", emitSelect(nonzero,
                                        bitFlag(result, size * 8 - 1, size),
                                        flag("SF"), 1));
            if (dstMem)
                out.ops.push_back(PcodeOp{POp::STORE, 0, dstId, 0, result});
            else
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && (name == "shld" || name == "shrd") &&
            out.named.count("dst") && out.named.count("src")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const bool dstMem = isMemory("dst");
            const int size = dstMem ? xc.opsz
                                    : (dstNode && dstNode->size
                                           ? dstNode->size : xc.opsz);
            const int bits = size * 8;
            const uint64_t destination = dstMem ? loadValue(dstId, size)
                                                : resized(dstId, size, false);
            const uint64_t source = resized(out.named["src"], size, false);
            uint64_t count = out.named.count("imm")
                                 ? resized(out.named["imm"], size, false)
                                 : resized(x86RegVarnode(1, 1), size, false);
            count = emit2(POp::INT_AND, count,
                          constVarnode(out, size == 8 ? 0x3f : 0x1f, size), size);
            const uint64_t zero = constVarnode(out, 0, size);
            const uint64_t one = constVarnode(out, 1, size);
            const uint64_t nonzero = emit2(POp::INT_NOTEQUAL, count, zero, 1);
            const uint64_t complementary = emit2(
                POp::INT_SUB, constVarnode(out, bits, size), count, size);
            uint64_t candidate = 0, carry = 0;
            if (name == "shld") {
                candidate = emit2(
                    POp::INT_OR,
                    emit2(POp::INT_LEFT, destination, count, size),
                    emit2(POp::INT_RIGHT, source, complementary, size), size);
                carry = emit2(POp::INT_AND,
                              emit2(POp::INT_RIGHT, destination,
                                    complementary, size), one, 1);
            } else {
                candidate = emit2(
                    POp::INT_OR,
                    emit2(POp::INT_RIGHT, destination, count, size),
                    emit2(POp::INT_LEFT, source, complementary, size), size);
                const uint64_t carryPosition = emit2(POp::INT_SUB, count, one, size);
                carry = emit2(POp::INT_AND,
                              emit2(POp::INT_RIGHT, destination,
                                    carryPosition, size), one, 1);
            }
            const uint64_t result = emitSelect(nonzero, candidate, destination, size);
            writeFlag("CF", emitSelect(nonzero, carry, flag("CF"), 1));
            const uint64_t isOne = emit2(POp::INT_EQUAL, count, one, 1);
            const uint64_t overflow = name == "shld"
                ? emit2(POp::INT_XOR, bitFlag(result, bits - 1, size), carry, 1)
                : emit2(POp::INT_XOR, bitFlag(destination, bits - 1, size),
                        bitFlag(result, bits - 1, size), 1);
            writeFlag("OF", emitSelect(isOne, overflow, flag("OF"), 1));
            writeFlag("PF", emitSelect(nonzero,
                                        emit1(POp::INT_PARITY, result, 1),
                                        flag("PF"), 1));
            writeFlag("ZF", emitSelect(nonzero,
                                        emit2(POp::INT_EQUAL, result, zero, 1),
                                        flag("ZF"), 1));
            writeFlag("SF", emitSelect(nonzero,
                                        bitFlag(result, bits - 1, size),
                                        flag("SF"), 1));
            if (dstMem)
                out.ops.push_back(PcodeOp{POp::STORE, 0, dstId, 0, result});
            else
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && (name == "rol" || name == "ror" ||
                            name == "rcl" || name == "rcr") &&
            out.named.count("dst")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const bool dstMem = isMemory("dst");
            const int size = byteOpcode(readByte(0)) ? 1
                                 : (dstMem ? xc.opsz
                                           : (dstNode ? dstNode->size : xc.opsz));
            const int bits = size * 8;
            const uint64_t value = dstMem ? loadValue(dstId, size)
                                          : resized(dstId, size, false);
            uint64_t count = constVarnode(out, 1, size);
            if (out.named.count("imm")) count = resized(out.named["imm"], size, false);
            else if (readByte(0) == 0xD2 || readByte(0) == 0xD3)
                count = resized(x86RegVarnode(1, 1), size, false);
            count = emit2(POp::INT_AND, count,
                          constVarnode(out, size == 8 ? 0x3f : 0x1f, size), size);
            const bool throughCarry = name == "rcl" || name == "rcr";
            count = emit2(POp::INT_REM, count,
                          constVarnode(out, bits + (throughCarry ? 1 : 0), size), size);
            const uint64_t zero = constVarnode(out, 0, size);
            const uint64_t one = constVarnode(out, 1, size);
            const uint64_t nonzero = emit2(POp::INT_NOTEQUAL, count, zero, 1);
            const uint64_t oldCF = flag("CF"), oldOF = flag("OF");
            uint64_t result = value, cfCandidate = oldCF;
            if (name == "rol" || name == "ror") {
                const uint64_t other = emit2(POp::INT_SUB,
                                             constVarnode(out, bits, size), count, size);
                const uint64_t left = emit2(POp::INT_LEFT, value,
                                            name == "rol" ? count : other, size);
                const uint64_t right = emit2(POp::INT_RIGHT, value,
                                             name == "rol" ? other : count, size);
                result = emit2(POp::INT_OR, left, right, size);
                cfCandidate = name == "rol" ? emit2(POp::INT_AND, result, one, 1)
                                             : bitFlag(result, bits - 1, size);
            } else {
                const uint64_t cin = resized(oldCF, size, false);
                if (name == "rcl") {
                    const uint64_t left = emit2(POp::INT_LEFT, value, count, size);
                    const uint64_t cinPos = emit2(POp::INT_SUB, count, one, size);
                    const uint64_t cinPart = emit2(POp::INT_LEFT, cin, cinPos, size);
                    const uint64_t rightPos = emit2(
                        POp::INT_SUB, constVarnode(out, bits + 1, size), count, size);
                    const uint64_t right = emit2(POp::INT_RIGHT, value, rightPos, size);
                    result = emit2(POp::INT_OR, emit2(POp::INT_OR, left, cinPart, size),
                                   right, size);
                    const uint64_t cfPos = emit2(POp::INT_SUB,
                                                 constVarnode(out, bits, size), count, size);
                    cfCandidate = emit2(POp::INT_AND,
                                        emit2(POp::INT_RIGHT, value, cfPos, size), one, 1);
                } else {
                    const uint64_t right = emit2(POp::INT_RIGHT, value, count, size);
                    const uint64_t cinPos = emit2(
                        POp::INT_SUB, constVarnode(out, bits, size), count, size);
                    const uint64_t cinPart = emit2(POp::INT_LEFT, cin, cinPos, size);
                    const uint64_t leftPos = emit2(
                        POp::INT_SUB, constVarnode(out, bits + 1, size), count, size);
                    const uint64_t left = emit2(POp::INT_LEFT, value, leftPos, size);
                    result = emit2(POp::INT_OR, emit2(POp::INT_OR, right, cinPart, size),
                                   left, size);
                    const uint64_t cfPos = emit2(POp::INT_SUB, count, one, size);
                    cfCandidate = emit2(POp::INT_AND,
                                        emit2(POp::INT_RIGHT, value, cfPos, size), one, 1);
                }
            }
            result = emitSelect(nonzero, result, value, size);
            writeFlag("CF", emitSelect(nonzero, cfCandidate, oldCF, 1));
            const uint64_t isOne = emit2(POp::INT_EQUAL, count, one, 1);
            const uint64_t msb = bitFlag(result, bits - 1, size);
            const uint64_t ofCandidate = (name == "rol" || name == "rcl")
                                             ? emit2(POp::INT_XOR, msb, cfCandidate, 1)
                                             : emit2(POp::INT_XOR, msb,
                                                     bitFlag(result, bits - 2, size), 1);
            writeFlag("OF", emitSelect(isOne, ofCandidate, oldOF, 1));
            if (dstMem)
                out.ops.push_back(PcodeOp{POp::STORE, 0, dstId, 0, result});
            else
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && (name == "bextr" || name == "andn" ||
                            name == "shlx" || name == "shrx" ||
                            name == "sarx" || name == "pdep" ||
                            name == "pext") &&
            out.named.count("dst") && out.named.count("src1") &&
            out.named.count("src2")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size ? dstNode->size
                                                       : (xc.vexW ? 8 : 4);
            const uint64_t src1 = resized(out.named["src1"], size, false);
            const uint64_t src2 = isMemory("src2")
                                      ? loadValue(out.named["src2"], size)
                                      : resized(out.named["src2"], size, false);
            uint64_t result = 0;
            if (name == "bextr") {
                const uint64_t start = emit2(
                    POp::INT_AND, src1, constVarnode(out, 0xff, size), size);
                const uint64_t length = emit2(
                    POp::INT_AND,
                    emit2(POp::INT_RIGHT, src1,
                          constVarnode(out, 8, size), size),
                    constVarnode(out, 0xff, size), size);
                const uint64_t shifted = emit2(POp::INT_RIGHT, src2, start, size);
                const uint64_t highBit = emit2(POp::INT_LEFT,
                                               constVarnode(out, 1, size),
                                               length, size);
                const uint64_t mask = emit2(POp::INT_SUB, highBit,
                                             constVarnode(out, 1, size), size);
                result = emit2(POp::INT_AND, shifted, mask, size);
                writeFlag("ZF", emit2(POp::INT_EQUAL, result,
                                        constVarnode(out, 0, size), 1));
            } else if (name == "andn") {
                const uint64_t inverted = emit2(
                    POp::INT_XOR, src1,
                    constVarnode(out, size == 8 ? ~0ULL
                                                : ((1ULL << (size * 8)) - 1),
                                  size), size);
                result = emit2(POp::INT_AND, inverted, src2, size);
                const uint64_t zero = constVarnode(out, 0, 1);
                writeFlag("CF", zero); writeFlag("OF", zero);
                writeFlag("ZF", emit2(POp::INT_EQUAL, result,
                                        constVarnode(out, 0, size), 1));
                writeFlag("SF", bitFlag(result, size * 8 - 1, size));
            } else if (name == "pdep" || name == "pext") {
                result = emit2(name == "pdep" ? POp::INT_PDEP : POp::INT_PEXT,
                               src1, src2, size);
            } else {
                const uint64_t count = emit2(
                    POp::INT_AND, src1,
                    constVarnode(out, size == 8 ? 0x3f : 0x1f, size), size);
                const POp operation = name == "shlx" ? POp::INT_LEFT
                                      : name == "shrx" ? POp::INT_RIGHT
                                                       : POp::INT_SRIGHT;
                result = emit2(operation, src2, count, size);
            }
            out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            x86Handled = result != 0;
        }

        if (!x86Handled && (name == "bsf" || name == "bsr" ||
                            name == "tzcnt" || name == "lzcnt" ||
                            name == "popcnt") && out.named.count("dst") &&
            out.named.count("src")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size ? dstNode->size : xc.opsz;
            const uint64_t srcId = out.named["src"];
            const uint64_t src = isMemory("src") ? loadValue(srcId, size)
                                                   : resized(srcId, size, false);
            const uint64_t zero = constVarnode(out, 0, size);
            const uint64_t inputZero = emit2(POp::INT_EQUAL, src, zero, 1);
            POp countOp = (name == "bsf" || name == "tzcnt")
                              ? POp::INT_COUNT_TRAILING_ZERO
                              : POp::INT_COUNT_LEADING_ZERO;
            uint64_t result = name == "popcnt"
                                  ? emit1(POp::INT_POPCOUNT, src, size)
                                  : emit1(countOp, src, size);
            if (name == "bsr")
                result = emit2(POp::INT_SUB,
                               constVarnode(out, size * 8 - 1, size), result, size);
            if (name == "bsf" || name == "bsr") {
                result = emitSelect(inputZero, dstId, result, size);
                writeFlag("ZF", inputZero);
            } else if (name == "popcnt") {
                writeFlag("ZF", inputZero);
                const uint64_t flagZero = constVarnode(out, 0, 1);
                writeFlag("CF", flagZero); writeFlag("OF", flagZero);
                writeFlag("SF", flagZero); writeFlag("AF", flagZero);
                writeFlag("PF", flagZero);
            } else {
                writeFlag("CF", inputZero);
                writeFlag("ZF", emit2(POp::INT_EQUAL, result, zero, 1));
                const uint64_t flagZero = constVarnode(out, 0, 1);
                writeFlag("OF", flagZero); writeFlag("SF", flagZero);
                writeFlag("AF", flagZero); writeFlag("PF", flagZero);
            }
            out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && (name == "bt" || name == "bts" ||
                            name == "btr" || name == "btc") &&
            out.named.count("dst")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const bool dstMem = isMemory("dst");
            const int size = dstMem ? xc.opsz
                                    : (dstNode && dstNode->size ? dstNode->size : xc.opsz);
            const uint64_t value = dstMem ? loadValue(dstId, size)
                                          : resized(dstId, size, false);
            std::string bitName = out.named.count("src") ? "src" : "imm";
            if (out.named.count(bitName)) {
                uint64_t bit = resized(out.named[bitName], size, false);
                bit = emit2(POp::INT_AND, bit,
                            constVarnode(out, size * 8 - 1, size), size);
                const uint64_t shifted = emit2(POp::INT_RIGHT, value, bit, size);
                writeFlag("CF", emit2(POp::INT_AND, shifted,
                                      constVarnode(out, 1, size), 1));
                if (name != "bt") {
                    const uint64_t mask = emit2(POp::INT_LEFT,
                                                constVarnode(out, 1, size), bit, size);
                    uint64_t result = value;
                    if (name == "bts") result = emit2(POp::INT_OR, value, mask, size);
                    else if (name == "btc") result = emit2(POp::INT_XOR, value, mask, size);
                    else result = emit2(POp::INT_AND, value,
                                        emit2(POp::INT_XOR, mask,
                                              constVarnode(out,
                                                           size >= 8 ? ~0ULL
                                                                     : ((1ULL << (size * 8)) - 1),
                                                           size), size),
                                        size);
                    if (dstMem)
                        out.ops.push_back(PcodeOp{POp::STORE, 0, dstId, 0, result});
                    else
                        out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                }
                x86Handled = true;
            }
        }

        // x87 uses a logical eight-entry stack of 80-bit IEEE extended
        // values.  Model the logical stack directly; this is equivalent to
        // rotating the architectural TOP field and makes SSA/data-flow
        // recovery substantially clearer than exposing physical stack slots.
        const bool x87Name = !name.empty() && name[0] == 'f' &&
                             name != "fs";
        if (!x86Handled && x87Name) {
            std::vector<uint64_t> st(8);
            // x87 logical stack lives at 24576+i*16; 12288..12304 is the
            // FS/GS segment-base register space (X86_FS_BASE_OFFSET).  They
            // used to collide (ST(0)==FS), so every x87 multiply in MSVC
            // builds decompiled into simd_mul_f32(fsbase, ...) with a scalar
            // second operand and failed to compile.
            for (size_t i = 0; i < st.size(); ++i) {
                Varnode* value = makeVarnode(
                    out, Varnode::REGISTER, 24576 + i * 16, 10,
                    "st" + std::to_string(i));
                st[i] = value->id;
            }
            const uint64_t controlWord = makeVarnode(
                out, Varnode::REGISTER, 12416, 2, "fcw")->id;
            const uint64_t statusWord = makeVarnode(
                out, Varnode::REGISTER, 12418, 2, "fsw")->id;
            const uint64_t tagWord = makeVarnode(
                out, Varnode::REGISTER, 12420, 2, "ftw")->id;
            auto convertFloat = [&](uint64_t value, int sourceBits,
                                    int destinationBits) {
                if (sourceBits == destinationBits) return value;
                const uint64_t converted = tmp(destinationBits / 8);
                const uint16_t format = static_cast<uint16_t>(
                    sourceBits | (destinationBits << 8));
                out.ops.push_back(PcodeOp{POp::FLOAT_FLOAT2FLOAT, converted,
                                          value, 0, 0, format});
                return converted;
            };
            auto pushX87 = [&](uint64_t value) {
                out.ops.push_back(PcodeOp{POp::X87_PUSH, 0, value, 0, 0});
            };
            auto popX87 = [&]() {
                out.ops.push_back(PcodeOp{POp::X87_POP, 0, 0, 0, 0});
            };
            auto requireX87 = [&](unsigned index) {
                out.ops.push_back(PcodeOp{POp::X87_REQUIRE, 0, 0, 0, 0,
                                          static_cast<uint16_t>(index & 7U)});
            };
            auto tagX87 = [&](unsigned index, uint64_t value) {
                out.ops.push_back(PcodeOp{POp::X87_TAG, 0, value, 0, 0,
                                          static_cast<uint16_t>(index & 7U)});
            };
            auto setX87Conditions = [&](uint64_t lhs, uint64_t rhs) {
                auto compare = [&](POp operation) {
                    const uint64_t result = tmp(1);
                    out.ops.push_back(PcodeOp{operation, result, lhs, rhs, 0, 80});
                    return result;
                };
                const uint64_t unordered = compare(POp::FLOAT_NAN);
                const uint64_t less = compare(POp::FLOAT_LESS);
                const uint64_t equal = compare(POp::FLOAT_EQUAL);
                const uint64_t c0 = emit2(POp::INT_OR, unordered, less, 1);
                const uint64_t c3 = emit2(POp::INT_OR, unordered, equal, 1);
                auto statusBit = [&](uint64_t value, unsigned bit) {
                    const uint64_t wide = resized(value, 2, false);
                    return emit2(POp::INT_LEFT, wide,
                                 constVarnode(out, bit, 2), 2);
                };
                uint64_t updated = emit2(POp::INT_AND, statusWord,
                                         constVarnode(out, 0xb8ff, 2), 2);
                updated = emit2(POp::INT_OR, updated, statusBit(c0, 8), 2);
                updated = emit2(POp::INT_OR, updated,
                                statusBit(unordered, 10), 2);
                updated = emit2(POp::INT_OR, updated, statusBit(c3, 14), 2);
                out.ops.push_back(PcodeOp{POp::COPY, statusWord, updated, 0, 0});
            };
            const uint8_t primary = readByte(0);
            const int memoryFloatBits = (primary == 0xD8 || primary == 0xD9) ? 32
                                        : (primary == 0xDC || primary == 0xDD) ? 64
                                        : 80;

            if (name == "fld" && out.named.count("dst") && isMemory("dst")) {
                uint64_t value = loadValue(out.named["dst"], memoryFloatBits / 8);
                value = convertFloat(value, memoryFloatBits, 80);
                pushX87(value);
                x86Handled = true;
            } else if (name == "fld1" || name == "fldz" ||
                       name == "fldl2t" || name == "fldl2e" ||
                       name == "fldpi" || name == "fldlg2" ||
                       name == "fldln2") {
                const uint16_t constant = name == "fld1" ? 0
                                          : name == "fldz" ? 1
                                          : name == "fldl2t" ? 2
                                          : name == "fldl2e" ? 3
                                          : name == "fldpi" ? 4
                                          : name == "fldlg2" ? 5 : 6;
                const uint64_t value = tmp(10);
                out.ops.push_back(PcodeOp{POp::X87_CONSTANT, value,
                                          0, 0, 0, constant});
                pushX87(value);
                x86Handled = true;
            } else if (name == "fld" && out.named.count("src")) {
                requireX87(xc.rm & 7);
                pushX87(st[xc.rm & 7]);
                x86Handled = true;
            } else if (name == "fldcw" && out.named.count("dst") &&
                       isMemory("dst")) {
                out.ops.push_back(PcodeOp{POp::COPY, controlWord,
                                          loadValue(out.named["dst"], 2), 0, 0});
                x86Handled = true;
            } else if (name == "fnstcw" && out.named.count("dst") &&
                       isMemory("dst")) {
                out.ops.push_back(PcodeOp{POp::STORE, 0, out.named["dst"], 0,
                                          controlWord});
                x86Handled = true;
            } else if (name == "fnstsw") {
                if (out.named.count("dst") && isMemory("dst"))
                    out.ops.push_back(PcodeOp{POp::STORE, 0, out.named["dst"], 0,
                                              statusWord});
                else
                    out.ops.push_back(PcodeOp{POp::COPY, x86RegVarnode(0, 2),
                                              statusWord, 0, 0});
                x86Handled = true;
            } else if (name == "fninit") {
                out.ops.push_back(PcodeOp{POp::COPY, controlWord,
                                          constVarnode(out, 0x037f, 2), 0, 0});
                out.ops.push_back(PcodeOp{POp::COPY, statusWord,
                                          constVarnode(out, 0, 2), 0, 0});
                out.ops.push_back(PcodeOp{POp::COPY, tagWord,
                                          constVarnode(out, 0xffff, 2), 0, 0});
                x86Handled = true;
            } else if (name == "fnclex") {
                out.ops.push_back(PcodeOp{
                    POp::COPY, statusWord,
                    emit2(POp::INT_AND, statusWord,
                          constVarnode(out, 0x7f00, 2), 2), 0, 0});
                x86Handled = true;
            } else if (name == "fchs" || name == "fabs") {
                requireX87(0);
                const uint64_t result = tmp(10);
                out.ops.push_back(PcodeOp{
                    name == "fchs" ? POp::FLOAT_NEG : POp::FLOAT_ABS,
                    result, st[0], 0, 0, 80});
                out.ops.push_back(PcodeOp{POp::COPY, st[0], result, 0, 0});
                tagX87(0, result);
                x86Handled = true;
            } else if (name == "fxam") {
                out.ops.push_back(PcodeOp{POp::X87_EXAMINE, 0, 0, 0, 0});
                x86Handled = true;
            } else if (name == "fdecstp" || name == "fincstp") {
                out.ops.push_back(PcodeOp{POp::X87_ROTATE, 0, 0, 0, 0,
                                          static_cast<uint16_t>(name == "fincstp")});
                x86Handled = true;
            } else if (name == "ftst") {
                requireX87(0);
                const uint64_t zero = tmp(10);
                out.ops.push_back(PcodeOp{POp::X87_CONSTANT, zero,
                                          0, 0, 0, 1});
                setX87Conditions(st[0], zero);
                x86Handled = true;
            } else if (name == "frndint" || name == "fsin" ||
                       name == "fcos" || name == "fsqrt" ||
                       name == "f2xm1") {
                requireX87(0);
                POp unary = name == "frndint" ? POp::FLOAT_ROUND
                            : name == "fsin" ? POp::FLOAT_SIN
                            : name == "fcos" ? POp::FLOAT_COS
                            : name == "fsqrt" ? POp::FLOAT_SQRT
                                               : POp::FLOAT_EXP2;
                const uint64_t transformed = tmp(10);
                out.ops.push_back(PcodeOp{unary, transformed, st[0],
                                          name == "frndint" ? controlWord : 0,
                                          0, 80});
                uint64_t result = transformed;
                if (name == "f2xm1") {
                    const double one = 1.0;
                    uint64_t bits = 0;
                    std::memcpy(&bits, &one, sizeof(bits));
                    const uint64_t one80 = convertFloat(
                        constVarnode(out, bits, 8), 64, 80);
                    result = tmp(10);
                    out.ops.push_back(PcodeOp{POp::FLOAT_SUB, result,
                                              transformed, one80, 0, 80});
                }
                out.ops.push_back(PcodeOp{POp::COPY, st[0], result, 0, 0});
                tagX87(0, result);
                x86Handled = true;
            } else if (name == "fptan" || name == "fsincos") {
                requireX87(0);
                const POp firstOperation = name == "fptan" ? POp::FLOAT_TAN
                                                            : POp::FLOAT_SIN;
                const uint64_t firstResult = tmp(10);
                out.ops.push_back(PcodeOp{firstOperation, firstResult, st[0],
                                          0, 0, 80});
                uint64_t pushed = 0;
                if (name == "fptan") {
                    const double one = 1.0;
                    uint64_t bits = 0;
                    std::memcpy(&bits, &one, sizeof(bits));
                    pushed = convertFloat(constVarnode(out, bits, 8), 64, 80);
                } else {
                    pushed = tmp(10);
                    out.ops.push_back(PcodeOp{POp::FLOAT_COS, pushed, st[0],
                                              0, 0, 80});
                }
                out.ops.push_back(PcodeOp{POp::COPY, st[0], firstResult, 0, 0});
                tagX87(0, firstResult);
                pushX87(pushed);
                x86Handled = true;
            } else if (name == "fpatan" || name == "fyl2x" ||
                       name == "fyl2xp1") {
                requireX87(0);
                requireX87(1);
                uint64_t result = tmp(10);
                if (name == "fpatan") {
                    out.ops.push_back(PcodeOp{POp::FLOAT_ATAN2, result,
                                              st[1], st[0], 0, 80});
                } else {
                    uint64_t logarithmInput = st[0];
                    if (name == "fyl2xp1") {
                        const double one = 1.0;
                        uint64_t bits = 0;
                        std::memcpy(&bits, &one, sizeof(bits));
                        const uint64_t one80 = convertFloat(
                            constVarnode(out, bits, 8), 64, 80);
                        logarithmInput = tmp(10);
                        out.ops.push_back(PcodeOp{POp::FLOAT_ADD,
                                                  logarithmInput, st[0],
                                                  one80, 0, 80});
                    }
                    const uint64_t logarithm = tmp(10);
                    out.ops.push_back(PcodeOp{POp::FLOAT_LOG2, logarithm,
                                              logarithmInput, 0, 0, 80});
                    out.ops.push_back(PcodeOp{POp::FLOAT_MULT, result,
                                              st[1], logarithm, 0, 80});
                }
                out.ops.push_back(PcodeOp{POp::COPY, st[1], result, 0, 0});
                tagX87(1, result);
                popX87();
                x86Handled = true;
            } else if (name == "fprem" || name == "fprem1" ||
                       name == "fscale") {
                requireX87(0);
                requireX87(1);
                const uint64_t result = tmp(10);
                out.ops.push_back(PcodeOp{
                    (name == "fprem" || name == "fprem1")
                        ? POp::FLOAT_REMAINDER : POp::FLOAT_SCALE,
                    result, st[0], st[1], 0,
                    static_cast<uint16_t>(80 | (name == "fprem" ? 0x0100 : 0))});
                out.ops.push_back(PcodeOp{POp::COPY, st[0], result, 0, 0});
                tagX87(0, result);
                x86Handled = true;
            } else if (name == "fxch") {
                requireX87(0);
                requireX87(xc.rm & 7);
                const uint64_t saved = tmp(10);
                out.ops.push_back(PcodeOp{POp::COPY, saved, st[0], 0, 0});
                out.ops.push_back(PcodeOp{POp::COPY, st[0], st[xc.rm & 7], 0, 0});
                out.ops.push_back(PcodeOp{POp::COPY, st[xc.rm & 7], saved, 0, 0});
                tagX87(0, st[0]);
                tagX87(xc.rm & 7, st[xc.rm & 7]);
                x86Handled = true;
            } else if (name == "ffree") {
                out.ops.push_back(PcodeOp{POp::X87_FREE, 0, 0, 0, 0,
                                          static_cast<uint16_t>(xc.rm & 7)});
                x86Handled = true;
            } else if ((name == "fild" || name == "filds") &&
                       out.named.count("dst") && isMemory("dst")) {
                const int integerSize = name == "filds" ? 2 : 4;
                const uint64_t integer = loadValue(out.named["dst"], integerSize);
                const uint64_t converted = tmp(10);
                out.ops.push_back(PcodeOp{POp::FLOAT_INT2FLOAT, converted,
                                          integer, 0, 0, 80});
                pushX87(converted);
                x86Handled = true;
            } else if ((name == "fst" || name == "fstp") &&
                       out.named.count("dst") && isMemory("dst")) {
                requireX87(0);
                const uint64_t value = convertFloat(st[0], 80, memoryFloatBits);
                out.ops.push_back(PcodeOp{POp::STORE, 0, out.named["dst"], 0, value});
                if (name == "fstp") popX87();
                x86Handled = true;
            } else if ((name == "fst" || name == "fstp") &&
                       out.named.count("dst")) {
                requireX87(0);
                out.ops.push_back(PcodeOp{POp::COPY, st[xc.rm & 7], st[0], 0, 0});
                tagX87(xc.rm & 7, st[0]);
                if (name == "fstp") popX87();
                x86Handled = true;
            } else if ((name == "fistp" || name == "fisttp") &&
                       out.named.count("dst") && isMemory("dst")) {
                requireX87(0);
                const int integerSize = primary == 0xDF ? 2
                                        : primary == 0xDB ? 4 : 8;
                const uint64_t value = tmp(integerSize);
                const uint16_t format = static_cast<uint16_t>(
                    80 | (name == "fisttp" ? 0x8000 : 0));
                out.ops.push_back(PcodeOp{POp::FLOAT_FLOAT2INT, value,
                                          st[0], 0, 0, format});
                out.ops.push_back(PcodeOp{POp::STORE, 0, out.named["dst"], 0, value});
                popX87();
                x86Handled = true;
            } else if (name == "fcom" || name == "fcomp" ||
                       name == "fucom" || name == "fucomp" ||
                       name == "ficom" || name == "ficomp" ||
                       name == "fcompp" || name == "fucompp") {
                requireX87(0);
                uint64_t rhs = st[xc.rm & 7];
                if (!(out.named.count("dst") && isMemory("dst")))
                    requireX87(xc.rm & 7);
                if (out.named.count("dst") && isMemory("dst")) {
                    if (name == "ficom" || name == "ficomp") {
                        const int integerSize = primary == 0xDE ? 2 : 4;
                        const uint64_t integer = loadValue(out.named["dst"],
                                                           integerSize);
                        rhs = tmp(10);
                        out.ops.push_back(PcodeOp{POp::FLOAT_INT2FLOAT, rhs,
                                                  integer, 0, 0, 80});
                    } else {
                        rhs = loadValue(out.named["dst"], memoryFloatBits / 8);
                        rhs = convertFloat(rhs, memoryFloatBits, 80);
                    }
                }
                out.ops.push_back(PcodeOp{
                    POp::X87_COMPARE_CHECK, 0, st[0], rhs, 0,
                    static_cast<uint16_t>(name.rfind("fu", 0) == 0
                                              ? 0x0100 : 0)});
                setX87Conditions(st[0], rhs);
                if (name == "fcomp" || name == "fucomp" ||
                    name == "ficomp" || name == "fcompp" ||
                    name == "fucompp")
                    popX87();
                if (name == "fcompp" || name == "fucompp") popX87();
                x86Handled = true;
            } else if (name == "fcomi" || name == "fucomi" ||
                       name == "fcomip" || name == "fucomip") {
                requireX87(0);
                requireX87(xc.rm & 7);
                const uint64_t rhs = st[xc.rm & 7];
                out.ops.push_back(PcodeOp{
                    POp::X87_COMPARE_CHECK, 0, st[0], rhs, 0,
                    static_cast<uint16_t>(name.rfind("fu", 0) == 0
                                              ? 0x0100 : 0)});
                auto compare = [&](POp operation) {
                    const uint64_t result = tmp(1);
                    out.ops.push_back(PcodeOp{operation, result, st[0], rhs,
                                              0, 80});
                    return result;
                };
                const uint64_t unordered = compare(POp::FLOAT_NAN);
                const uint64_t less = compare(POp::FLOAT_LESS);
                const uint64_t equal = compare(POp::FLOAT_EQUAL);
                writeFlag("CF", emit2(POp::INT_OR, unordered, less, 1));
                writeFlag("PF", unordered);
                writeFlag("ZF", emit2(POp::INT_OR, unordered, equal, 1));
                const uint64_t zero = constVarnode(out, 0, 1);
                writeFlag("OF", zero); writeFlag("SF", zero);
                writeFlag("AF", zero);
                if (name == "fcomip" || name == "fucomip") popX87();
                x86Handled = true;
            } else {
                POp operation = POp::UNIMPLEMENTED;
                if (name == "fadd" || name == "fiadd" || name == "faddp")
                    operation = POp::FLOAT_ADD;
                else if (name == "fmul" || name == "fimul" || name == "fmulp")
                    operation = POp::FLOAT_MULT;
                else if (name == "fsub" || name == "fisub" ||
                         name == "fsubp" || name == "fsubrp")
                    operation = POp::FLOAT_SUB;
                else if (name == "fsubr" || name == "fisubr")
                    operation = POp::FLOAT_SUB;
                else if (name == "fdiv" || name == "fidiv" ||
                         name == "fdivp" || name == "fdivrp")
                    operation = POp::FLOAT_DIV;
                else if (name == "fdivr" || name == "fidivr")
                    operation = POp::FLOAT_DIV;
                if (operation != POp::UNIMPLEMENTED) {
                    requireX87(0);
                    uint64_t rhs = st[xc.rm & 7];
                    if (!(out.named.count("dst") && isMemory("dst")))
                        requireX87(xc.rm & 7);
                    if (out.named.count("dst") && isMemory("dst")) {
                        if (name.size() > 1 && name[1] == 'i') {
                            const int integerSize = primary == 0xDE ? 2 : 4;
                            const uint64_t integer = loadValue(out.named["dst"], integerSize);
                            rhs = tmp(10);
                            out.ops.push_back(PcodeOp{POp::FLOAT_INT2FLOAT, rhs,
                                                      integer, 0, 0, 80});
                        } else {
                            rhs = loadValue(out.named["dst"], memoryFloatBits / 8);
                            rhs = convertFloat(rhs, memoryFloatBits, 80);
                        }
                    }
                    const bool reverse = name == "fsubr" || name == "fisubr" ||
                                         name == "fdivr" || name == "fidivr" ||
                                         name == "fsubrp" || name == "fdivrp";
                    const bool popArithmetic = xc.mod == 3 && primary == 0xDE;
                    const bool registerDestination = xc.mod == 3 &&
                                                     (primary == 0xDC ||
                                                      popArithmetic);
                    const uint64_t destination = registerDestination
                                                     ? st[xc.rm & 7] : st[0];
                    const uint64_t lhs = registerDestination ? destination : st[0];
                    const uint64_t other = registerDestination ? st[0] : rhs;
                    const uint64_t result = tmp(10);
                    out.ops.push_back(PcodeOp{operation, result,
                                              reverse ? other : lhs,
                                              reverse ? lhs : other, 0, 80});
                    out.ops.push_back(PcodeOp{POp::COPY, destination, result, 0, 0});
                    tagX87(registerDestination ? (xc.rm & 7) : 0, result);
                    if (popArithmetic) popX87();
                    x86Handled = true;
                }
            }
        }

        if (!x86Handled && (name == "pmovmskb" || name == "vpmovmskb" ||
                            name == "movmskps" || name == "movmskpd") &&
            out.named.count("dst") && out.named.count("src")) {
            const int laneBits = (name == "movmskps") ? 32
                                 : (name == "movmskpd") ? 64 : 8;
            out.ops.push_back(PcodeOp{
                POp::SIMD_MOVEMASK, out.named["dst"], out.named["src"],
                0, 0, static_cast<uint16_t>(laneBits)});
            x86Handled = true;
        }

        // Legacy MOVSS/MOVSD replace only the low scalar lane and preserve
        // the remaining destination XMM bits. Store encodings use the
        // opposite ModRM direction from loads.
        if (!x86Handled && (name == "movss" || name == "movsd") &&
            readByte(0) == 0x0F && out.named.count("dst") &&
            out.named.count("src")) {
            const int laneBits = name == "movss" ? 32 : 64;
            const int laneBytes = laneBits / 8;
            const uint64_t dstId = out.named["dst"];
            const uint64_t srcId = out.named["src"];
            const uint64_t zero = constVarnode(out, 0, 1);
            if (isMemory("dst")) {
                uint64_t low = tmp(laneBytes);
                out.ops.push_back(PcodeOp{POp::SIMD_EXTRACT, low, srcId,
                                          zero, 0,
                                          static_cast<uint16_t>(laneBits)});
                out.ops.push_back(PcodeOp{POp::STORE, 0, dstId, 0, low});
            } else {
                const uint64_t lane = isMemory("src")
                                          ? loadValue(srcId, laneBytes) : srcId;
                const uint64_t result = tmp(16);
                out.ops.push_back(PcodeOp{POp::SIMD_INSERT, result, dstId,
                                          lane, zero,
                                          static_cast<uint16_t>(laneBits)});
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            }
            x86Handled = true;
        }

        // MOVQ transfers a low qword between scalar/memory and XMM forms.
        // XMM destinations are zero-filled above bit 63, including VEX forms.
        if (!x86Handled && (name == "movq" || name == "vmovq") &&
            out.named.count("dst") && out.named.count("src")) {
            const uint64_t dstId = out.named["dst"];
            const uint64_t srcId = out.named["src"];
            const Varnode* dstNode = out.find(dstId);
            const Varnode* srcNode = out.find(srcId);
            const bool vectorDestination = dstNode && dstNode->size > 8;
            const bool vectorSource = srcNode && srcNode->size > 8;
            uint64_t low = srcId;
            if (isMemory("src")) {
                low = loadValue(srcId, 8);
            } else if (vectorSource) {
                low = tmp(8);
                out.ops.push_back(PcodeOp{
                    POp::SIMD_EXTRACT, low, srcId,
                    constVarnode(out, 0, 1), 0, 64});
            }
            if (vectorDestination) {
                out.ops.push_back(PcodeOp{POp::COPY, dstId, low, 0, 0});
            } else if (isMemory("dst")) {
                out.ops.push_back(PcodeOp{POp::STORE, 0, dstId, 0, low});
            } else {
                out.ops.push_back(PcodeOp{POp::COPY, dstId, low, 0, 0});
            }
            x86Handled = true;
        }

        // MOVD transfers exactly one dword between a GPR/memory operand and
        // the low XMM lane.  A vector destination is zero-filled above bit
        // 31; a scalar destination receives only the extracted low dword.
        if (!x86Handled && (name == "movd" || name == "vmovd") &&
            out.named.count("dst") && out.named.count("src")) {
            const uint64_t dstId = out.named["dst"];
            const uint64_t srcId = out.named["src"];
            const Varnode* dstNode = out.find(dstId);
            const bool vectorDestination = dstNode && dstNode->size > 8;
            if (vectorDestination) {
                const uint64_t value = isMemory("src")
                                           ? loadValue(srcId, 4) : srcId;
                out.ops.push_back(PcodeOp{POp::COPY, dstId, value, 0, 0});
            } else {
                const uint64_t low = tmp(4);
                const uint64_t zero = constVarnode(out, 0, 1);
                out.ops.push_back(PcodeOp{POp::SIMD_EXTRACT, low, srcId,
                                          zero, 0, 32});
                if (isMemory("dst"))
                    out.ops.push_back(PcodeOp{POp::STORE, 0, dstId, 0, low});
                else
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, low, 0, 0});
            }
            x86Handled = true;
        }

        if (!x86Handled && out.named.count("dst") && out.named.count("imm")) {
            std::string insertName = name;
            if (!insertName.empty() && insertName[0] == 'v')
                insertName.erase(insertName.begin());
            const int laneBits = insertName == "pinsrb" ? 8
                               : insertName == "pinsrw" ? 16
                               : insertName == "pinsrd" ? 32
                               : insertName == "pinsrq" ? 64 : 0;
            const std::string sourceOperand = name[0] == 'v' ? "src2" : "src";
            if (laneBits && out.named.count(sourceOperand)) {
                const uint64_t dstId = out.named["dst"];
                const Varnode* dstNode = out.find(dstId);
                const int size = dstNode && dstNode->size > 8
                                     ? dstNode->size : 16;
                const uint64_t base = name[0] == 'v' && out.named.count("src1")
                                          ? out.named["src1"] : dstId;
                const uint64_t lane = isMemory(sourceOperand)
                                          ? loadValue(out.named[sourceOperand],
                                                      laneBits / 8)
                                          : out.named[sourceOperand];
                const uint64_t result = tmp(size);
                out.ops.push_back(PcodeOp{
                    POp::SIMD_INSERT, result, base, lane, out.named["imm"],
                    static_cast<uint16_t>(laneBits)});
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            }
        }

        if (!x86Handled &&
            (name == "movlps" || name == "movlpd" ||
             name == "movhps" || name == "movhpd") &&
            out.named.count("dst") && out.named.count("src")) {
            const bool high = name[3] == 'h';
            const uint64_t index = constVarnode(out, high ? 1 : 0, 1);
            if (isMemory("src")) {
                const uint64_t lane = loadValue(out.named["src"], 8);
                const uint64_t result = tmp(16);
                out.ops.push_back(PcodeOp{POp::SIMD_INSERT, result,
                                          out.named["dst"], lane, index, 64});
                out.ops.push_back(PcodeOp{POp::COPY, out.named["dst"],
                                          result, 0, 0});
            } else if (isMemory("dst")) {
                const uint64_t lane = tmp(8);
                out.ops.push_back(PcodeOp{POp::SIMD_EXTRACT, lane,
                                          out.named["src"], index, 0, 64});
                out.ops.push_back(PcodeOp{POp::STORE, 0, out.named["dst"],
                                          0, lane});
            }
            x86Handled = true;
        }

        if (!x86Handled && (name == "movhlps" || name == "movlhps") &&
            out.named.count("dst") && out.named.count("src")) {
            const bool highToLow = name == "movhlps";
            const uint64_t sourceIndex = constVarnode(out, highToLow ? 1 : 0, 1);
            const uint64_t destinationIndex = constVarnode(out, highToLow ? 0 : 1, 1);
            const uint64_t lane = tmp(8);
            out.ops.push_back(PcodeOp{POp::SIMD_EXTRACT, lane,
                                      out.named["src"], sourceIndex, 0, 64});
            const uint64_t result = tmp(16);
            out.ops.push_back(PcodeOp{POp::SIMD_INSERT, result,
                                      out.named["dst"], lane,
                                      destinationIndex, 64});
            out.ops.push_back(PcodeOp{POp::COPY, out.named["dst"], result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled &&
            (name == "movntdq" || name == "movntps" ||
             name == "movntpd" || name == "movnti") &&
            out.named.count("dst") && out.named.count("src") &&
            isMemory("dst")) {
            const Varnode* sourceNode = out.find(out.named["src"]);
            const int size = name == "movnti"
                                 ? (sourceNode ? sourceNode->size : xc.opsz)
                                 : (sourceNode && sourceNode->size > 8
                                        ? sourceNode->size : 16);
            const uint64_t value = resized(out.named["src"], size, false);
            out.ops.push_back(PcodeOp{POp::STORE, 0, out.named["dst"], 0, value});
            x86Handled = true;
        }

        if (!x86Handled && (name == "vzeroupper" || name == "vzeroall")) {
            const int size = 32;
            const uint64_t zero = constVarnode(out, 0, size);
            for (int index = 0; index < 16; ++index) {
                const uint64_t reg = x86RegVarnode(index, size);
                out.ops.push_back(PcodeOp{
                    name == "vzeroall" ? POp::COPY : POp::SIMD_ZERO_UPPER,
                    reg, name == "vzeroall" ? zero : reg, 0, 0});
            }
            x86Handled = true;
        }

        if (!x86Handled && name == "vinsertf128" &&
            out.named.count("dst") && out.named.count("src1") &&
            out.named.count("src2") && out.named.count("imm")) {
            const uint64_t lane = isMemory("src2")
                                      ? loadValue(out.named["src2"], 16)
                                      : out.named["src2"];
            const uint64_t result = tmp(32);
            out.ops.push_back(PcodeOp{POp::SIMD_INSERT, result,
                                      out.named["src1"], lane,
                                      out.named["imm"], 128});
            out.ops.push_back(PcodeOp{POp::COPY, out.named["dst"], result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && name == "vperm2f128" &&
            out.named.count("dst") && out.named.count("src1") &&
            out.named.count("src2") && out.named.count("imm")) {
            const uint64_t source2 = isMemory("src2")
                                         ? loadValue(out.named["src2"], 32)
                                         : out.named["src2"];
            const uint64_t result = tmp(32);
            out.ops.push_back(PcodeOp{POp::SIMD_PERMUTE128, result,
                                      out.named["src1"], source2,
                                      out.named["imm"]});
            out.ops.push_back(PcodeOp{POp::COPY, out.named["dst"], result, 0, 0});
            x86Handled = true;
        }

        // Full-width aligned/unaligned SIMD moves.  Store encodings reverse
        // the ModRM roles relative to load encodings, so use the opcode rather
        // than the constructor's display operand names.
        if (!x86Handled && out.named.count("dst") && out.named.count("src") &&
            out.named.count("imm")) {
            std::string extractName = name;
            if (!extractName.empty() && extractName[0] == 'v')
                extractName.erase(extractName.begin());
            int laneBits = extractName == "pextrb" ? 8
                           : extractName == "pextrw" ? 16
                           : (extractName == "pextrd" || extractName == "extractps") ? 32
                           : extractName == "pextrq" ? 64
                           : (extractName == "extractf128" ||
                              extractName == "extracti32x4") ? 128 : 0;
            if (laneBits) {
                const int laneSize = laneBits / 8;
                const uint64_t extracted = tmp(laneSize);
                out.ops.push_back(PcodeOp{
                    POp::SIMD_EXTRACT, extracted, out.named["src"],
                    out.named["imm"], 0, static_cast<uint16_t>(laneBits)});
                if (isMemory("dst"))
                    out.ops.push_back(PcodeOp{POp::STORE, 0, out.named["dst"],
                                              0, extracted});
                else
                    out.ops.push_back(PcodeOp{POp::COPY, out.named["dst"],
                                              extracted, 0, 0});
                x86Handled = true;
            }
        }

        if (!x86Handled && out.named.count("dst") && out.named.count("src")) {
            std::string moveName = name;
            if (!moveName.empty() && moveName[0] == 'v') moveName.erase(moveName.begin());
            const std::set<std::string> vectorMoves = {
                "movups", "movupd", "movaps", "movapd", "movdqa", "movdqu",
                "movdqa32", "movdqa64", "movdqu32", "movdqu64"
            };
            if (vectorMoves.count(moveName)) {
                const int actualOpcode = (xc.vex || xc.evex) ? readByte(0) : readByte(1);
                const bool storeEncoding = actualOpcode == 0x11 || actualOpcode == 0x29 ||
                                           actualOpcode == 0x7F;
                const uint64_t dstId = out.named["dst"];
                const uint64_t srcId = out.named["src"];
                const Varnode* dstNode = out.find(dstId);
                const Varnode* srcNode = out.find(srcId);
                const int size = dstNode && dstNode->size > 8 ? dstNode->size
                                 : srcNode && srcNode->size > 8 ? srcNode->size : 16;
                const int laneBits = moveName.size() >= 2 &&
                                             moveName.substr(moveName.size() - 2) == "64"
                                         ? 64 : 32;
                if (storeEncoding) {
                    if (isMemory("dst") || isMemory("src")) {
                        const uint64_t address = isMemory("dst") ? dstId : srcId;
                        uint64_t value = isMemory("dst") ? srcId : dstId;
                        if (xc.evex && xc.evexAaa != 0) {
                            const uint64_t previous = loadValue(address, size);
                            value = applyEvexStoreMask(value, previous, size, laneBits);
                        }
                        out.ops.push_back(PcodeOp{POp::STORE, 0, address, 0, value});
                    } else {
                        out.ops.push_back(PcodeOp{POp::COPY, srcId, dstId, 0, 0});
                    }
                } else {
                    uint64_t value = isMemory("src") ? loadValue(srcId, size) : srcId;
                    value = applyEvexMask(value, dstId, size, laneBits);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, value, 0, 0});
                }
                x86Handled = true;
            }
        }

        if (!x86Handled && (name == "haddps" || name == "haddpd" ||
                            name == "hsubps" || name == "hsubpd") &&
            out.named.count("dst") && out.named.count("src")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size > 8 ? dstNode->size : 16;
            const bool f64 = name.size() >= 2 &&
                             name.substr(name.size() - 2) == "pd";
            const bool subtract = name.rfind("hsub", 0) == 0;
            const uint64_t source = isMemory("src")
                                        ? loadValue(out.named["src"], size)
                                        : out.named["src"];
            const uint64_t result = tmp(size);
            out.ops.push_back(PcodeOp{
                POp::SIMD_HORIZONTAL, result, dstId, source, 0,
                static_cast<uint16_t>((f64 ? 64 : 32) |
                                      (subtract ? 0x0100 : 0))});
            out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && (name == "cmpps" || name == "cmppd" ||
                            name == "cmpss" || name == "cmpsd") &&
            readByte(0) == 0x0F && out.named.count("dst") &&
            out.named.count("src") && out.named.count("imm")) {
            const bool f32 = name == "cmpps" || name == "cmpss";
            const bool scalar = name == "cmpss" || name == "cmpsd";
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size > 8 ? dstNode->size : 16;
            const uint64_t source = isMemory("src")
                                        ? loadValue(out.named["src"],
                                                    scalar ? (f32 ? 4 : 8) : size)
                                        : out.named["src"];
            const uint64_t result = tmp(size);
            out.ops.push_back(PcodeOp{
                POp::SIMD_FP_COMPARE, result, dstId, source, out.named["imm"],
                static_cast<uint16_t>((f32 ? 32 : 64) |
                                      (scalar ? 0x8000 : 0))});
            out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && (name == "addsubps" || name == "addsubpd" ||
                            name == "blendps" || name == "blendpd") &&
            out.named.count("dst") && out.named.count("src")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size > 8 ? dstNode->size : 16;
            const int laneBits = (name.size() >= 2 &&
                                  name.substr(name.size() - 2) == "pd") ? 64 : 32;
            const uint64_t source = isMemory("src")
                                        ? loadValue(out.named["src"], size)
                                        : out.named["src"];
            const uint64_t result = tmp(size);
            const bool blend = name.rfind("blend", 0) == 0;
            out.ops.push_back(PcodeOp{
                blend ? POp::SIMD_BLEND : POp::SIMD_ADDSUB,
                result, dstId, source,
                blend && out.named.count("imm") ? out.named["imm"] : 0,
                static_cast<uint16_t>(laneBits)});
            out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            x86Handled = true;
        }

        // Packed bitwise and wrapping integer lane operations.
        if (!x86Handled && out.named.count("dst")) {
            std::string vectorName = name;
            const bool vexVector = !vectorName.empty() && vectorName[0] == 'v';
            if (vexVector) vectorName.erase(vectorName.begin());
            POp vectorOp = POp::UNIMPLEMENTED;
            int laneBits = 0;
            bool invertLeft = false;
            if (vectorName == "andps" || vectorName == "andpd" ||
                vectorName == "pand" || vectorName == "pandd" ||
                vectorName == "pandq")
                vectorOp = POp::INT_AND;
            else if (vectorName == "andnps" || vectorName == "andnpd" ||
                     vectorName == "pandn") {
                vectorOp = POp::INT_AND;
                invertLeft = true;
            }
            else if (vectorName == "orps" || vectorName == "orpd" ||
                     vectorName == "por" || vectorName == "pord" ||
                     vectorName == "porq")
                vectorOp = POp::INT_OR;
            else if (vectorName == "xorps" || vectorName == "xorpd" ||
                     vectorName == "pxor" || vectorName == "pxord" ||
                     vectorName == "pxorq")
                vectorOp = POp::INT_XOR;
            else if (vectorName == "paddb") { vectorOp = POp::INT_ADD; laneBits = 8; }
            else if (vectorName == "paddw") { vectorOp = POp::INT_ADD; laneBits = 16; }
            else if (vectorName == "paddd") { vectorOp = POp::INT_ADD; laneBits = 32; }
            else if (vectorName == "paddq") { vectorOp = POp::INT_ADD; laneBits = 64; }
            else if (vectorName == "psubb") { vectorOp = POp::INT_SUB; laneBits = 8; }
            else if (vectorName == "psubw") { vectorOp = POp::INT_SUB; laneBits = 16; }
            else if (vectorName == "psubd") { vectorOp = POp::INT_SUB; laneBits = 32; }
            else if (vectorName == "psubq") { vectorOp = POp::INT_SUB; laneBits = 64; }
            else if (vectorName == "pmullw") { vectorOp = POp::INT_MULT; laneBits = 16; }
            else if (vectorName == "pmulld") { vectorOp = POp::INT_MULT; laneBits = 32; }
            if (vectorOp != POp::UNIMPLEMENTED) {
                const uint64_t dstId = out.named["dst"];
                const Varnode* dstNode = out.find(dstId);
                const int size = dstNode && dstNode->size ? dstNode->size : 16;
                uint64_t a = dstId, b = 0;
                if (vexVector && out.named.count("src1") && out.named.count("src2")) {
                    a = out.named["src1"];
                    b = isMemory("src2") ? loadValue(out.named["src2"], size)
                                          : out.named["src2"];
                } else if (out.named.count("src")) {
                    b = isMemory("src") ? loadValue(out.named["src"], size)
                                         : out.named["src"];
                }
                if (b) {
                    if (invertLeft) {
                        const uint64_t inverted = tmp(size);
                        out.ops.push_back(PcodeOp{POp::INT_NOT, inverted,
                                                  a, 0, 0});
                        a = inverted;
                    }
                    uint64_t result = tmp(size);
                    out.ops.push_back(PcodeOp{vectorOp, result, a, b, 0,
                                              static_cast<uint16_t>(laneBits)});
                    result = applyEvexMask(result, dstId, size,
                                           laneBits ? laneBits : 8);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }
        }

        if (!x86Handled && out.named.count("dst")) {
            std::string operationName = name;
            const bool vectorForm = !operationName.empty() &&
                                    operationName[0] == 'v';
            if (vectorForm) operationName.erase(operationName.begin());
            const bool average = operationName == "pavgb" ||
                                 operationName == "pavgw";
            const bool minmax = operationName == "pminub" ||
                                operationName == "pminsw" ||
                                operationName == "pmaxub" ||
                                operationName == "pmaxsw";
            const bool sad = operationName == "psadbw";
            if (average || minmax || sad) {
                const uint64_t dstId = out.named["dst"];
                const Varnode* dstNode = out.find(dstId);
                const int size = dstNode && dstNode->size > 8
                                     ? dstNode->size : 16;
                uint64_t left = dstId, right = 0;
                if (vectorForm && out.named.count("src1") &&
                    out.named.count("src2")) {
                    left = out.named["src1"];
                    right = isMemory("src2")
                                ? loadValue(out.named["src2"], size)
                                : out.named["src2"];
                } else if (out.named.count("src")) {
                    right = isMemory("src")
                                ? loadValue(out.named["src"], size)
                                : out.named["src"];
                }
                if (right) {
                    const int laneBits = operationName.back() == 'w' ? 16 : 8;
                    const bool signedValues = operationName == "pminsw" ||
                                              operationName == "pmaxsw";
                    const bool maximum = operationName == "pmaxub" ||
                                         operationName == "pmaxsw";
                    const uint16_t aux = static_cast<uint16_t>(
                        laneBits | (signedValues ? 0x0100 : 0) |
                        (maximum ? 0x0200 : 0));
                    const POp operation = average ? POp::SIMD_AVERAGE
                                          : minmax ? POp::SIMD_MINMAX
                                                   : POp::SIMD_SAD;
                    uint64_t result = tmp(size);
                    out.ops.push_back(PcodeOp{operation, result, left, right,
                                              0, aux});
                    result = applyEvexMask(result, dstId, size,
                                           sad ? 64 : laneBits);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }
        }

        // AVX2/AVX-512 VSIB gather/scatter.  The SIB index names a vector
        // register rather than a GPR; base/displacement remain scalar and
        // every active k-mask lane performs an independently faultable access.
        const bool gather = name == "vpgatherdd" || name == "vpgatherdq" ||
                            name == "vpgatherqd" || name == "vpgatherqq";
        const bool scatter = name == "vpscatterdd" || name == "vpscatterdq" ||
                             name == "vpscatterqd" || name == "vpscatterqq";
        if (!x86Handled && (gather || scatter) && xc.index >= 0) {
            const std::string suffix = name.substr(name.size() - 2);
            const int laneBits = suffix[1] == 'q' ? 64 : 32;
            const bool index64 = suffix[0] == 'q';
            const std::string vectorOperand = gather ? "dst" : "src";
            if (out.named.count(vectorOperand)) {
                const uint64_t vectorId = out.named[vectorOperand];
                const Varnode* vectorNode = out.find(vectorId);
                const int vectorSize = vectorNode && vectorNode->size
                                           ? vectorNode->size : 64;
                uint64_t base = 0;
                if (xc.ripRel) {
                    base = constVarnode(out,
                                        addr + insnSize +
                                            static_cast<uint64_t>(xc.disp), 8);
                } else {
                    base = xc.base >= 0 ? x86RegVarnode(xc.base, 8)
                                        : constVarnode(out, 0, 8);
                    if (xc.disp) {
                        const uint64_t adjusted = tmp(8);
                        out.ops.push_back(PcodeOp{
                            POp::INT_ADD, adjusted, base,
                            constVarnode(out, static_cast<uint64_t>(xc.disp), 8),
                            0});
                        base = adjusted;
                    }
                }
                const int vectorIndex = xc.index | xc.evexVprime;
                const uint64_t indices = x86RegVarnode(vectorIndex, vectorSize);
                unsigned scaleShift = 0;
                while ((1U << scaleShift) < static_cast<unsigned>(xc.scale))
                    ++scaleShift;
                const uint16_t aux = static_cast<uint16_t>(
                    laneBits | (index64 ? 0x0100 : 0) |
                    (scaleShift << 9) | (xc.evexAaa << 11) |
                    (xc.evexZ ? 0x4000 : 0));
                if (gather)
                    out.ops.push_back(PcodeOp{POp::SIMD_GATHER, vectorId,
                                              base, indices, 0, aux});
                else
                    out.ops.push_back(PcodeOp{POp::SIMD_SCATTER, 0, base,
                                              indices, vectorId, aux});
                x86Handled = true;
            }
        }

        // AVX-512 comparisons produce compact k-register results.  The imm8
        // predicate implements EQ/LT/LE/FALSE/NE/NLT/NLE/TRUE, and an EVEX
        // writemask clears disabled result bits as required for k outputs.
        if (!x86Handled && (name == "vpcmpd" || name == "vpcmpq" ||
                            name == "vpcmpud" || name == "vpcmpuq") &&
            out.named.count("dst") && out.named.count("src1") &&
            out.named.count("src2") && out.named.count("imm")) {
            const int laneBits = (name == "vpcmpq" || name == "vpcmpuq")
                                     ? 64 : 32;
            const Varnode* sourceNode = out.find(out.named["src1"]);
            const int size = sourceNode && sourceNode->size
                                 ? sourceNode->size : 64;
            const uint64_t rhs = isMemory("src2")
                                     ? loadValue(out.named["src2"], size)
                                     : out.named["src2"];
            uint64_t result = tmp(8);
            const bool signedCompare = name == "vpcmpd" || name == "vpcmpq";
            out.ops.push_back(PcodeOp{
                POp::SIMD_COMPARE_MASK, result, out.named["src1"], rhs,
                out.named["imm"],
                static_cast<uint16_t>(laneBits |
                                      (signedCompare ? 0x0100 : 0))});
            if (xc.evexAaa != 0) {
                Varnode* writemask = makeVarnode(
                    out, Varnode::REGISTER,
                    8192 + static_cast<uint64_t>(xc.evexAaa) * 8, 8,
                    "k" + std::to_string(xc.evexAaa));
                result = emit2(POp::INT_AND, result, writemask->id, 8);
            }
            out.ops.push_back(PcodeOp{POp::COPY, out.named["dst"], result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && (name == "gf2p8mulb" || name == "vgf2p8mulb") &&
            out.named.count("dst")) {
            const bool vectorForm = name[0] == 'v';
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size > 8 ? dstNode->size : 16;
            uint64_t lhs = dstId, rhs = 0;
            if (vectorForm && out.named.count("src1") &&
                out.named.count("src2")) {
                lhs = out.named["src1"];
                rhs = isMemory("src2") ? loadValue(out.named["src2"], size)
                                        : out.named["src2"];
            } else if (out.named.count("src")) {
                rhs = isMemory("src") ? loadValue(out.named["src"], size)
                                       : out.named["src"];
            }
            if (rhs) {
                uint64_t result = tmp(size);
                out.ops.push_back(PcodeOp{POp::GF2P8_MUL, result, lhs, rhs, 0});
                if (vectorForm) result = applyEvexMask(result, dstId, size, 8);
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            }
        }

        // GFNI affine transformations select one 8x8 matrix per qword.  The
        // inverse form first computes multiplicative inverse in GF(2^8),
        // including the architecturally defined inverse(0) == 0 case.
        if (!x86Handled &&
            (name == "gf2p8affineqb" || name == "vgf2p8affineqb" ||
             name == "gf2p8affineinvqb" || name == "vgf2p8affineinvqb") &&
            out.named.count("dst") && out.named.count("imm")) {
            const bool vectorForm = name[0] == 'v';
            const bool inverse = name.find("affineinv") != std::string::npos;
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size > 8 ? dstNode->size : 16;
            uint64_t source = dstId, matrix = 0;
            if (vectorForm && out.named.count("src1") &&
                out.named.count("src2")) {
                source = out.named["src1"];
                matrix = isMemory("src2")
                             ? loadValue(out.named["src2"], size)
                             : out.named["src2"];
            } else if (out.named.count("src")) {
                matrix = isMemory("src") ? loadValue(out.named["src"], size)
                                           : out.named["src"];
            }
            if (matrix) {
                uint64_t result = tmp(size);
                out.ops.push_back(PcodeOp{
                    inverse ? POp::GF2P8_AFFINE_INV : POp::GF2P8_AFFINE,
                    result, source, matrix, out.named["imm"]});
                if (vectorForm) result = applyEvexMask(result, dstId, size, 8);
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            }
        }

        // PCLMULQDQ/VPCLMULQDQ perform independent 64x64 carry-less
        // products in each 128-bit lane; imm8 bits 0 and 4 select operands.
        if (!x86Handled &&
            (name == "pclmulqdq" || name == "vpclmulqdq" ||
             name == "vclmulqdq" || name == "vclmulhqhqdq" ||
             name == "vclmullqlqdq") && out.named.count("dst")) {
            const bool vectorForm = name[0] == 'v';
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size > 8 ? dstNode->size : 16;
            uint64_t lhs = dstId, rhs = 0;
            if (vectorForm && out.named.count("src1") &&
                out.named.count("src2")) {
                lhs = out.named["src1"];
                rhs = isMemory("src2") ? loadValue(out.named["src2"], size)
                                        : out.named["src2"];
            } else if (out.named.count("src")) {
                rhs = isMemory("src") ? loadValue(out.named["src"], size)
                                       : out.named["src"];
            }
            uint64_t immediate = out.named.count("imm") ? out.named["imm"] : 0;
            if (!immediate)
                immediate = constVarnode(out,
                    name == "vclmulhqhqdq" ? 0x11 : 0x00, 1);
            if (rhs) {
                uint64_t result = tmp(size);
                out.ops.push_back(PcodeOp{POp::CARRYLESS_MULT, result,
                                          lhs, rhs, immediate});
                if (xc.evex) result = applyEvexMask(result, dstId, size, 128);
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            }
        }

        // Intel SHA extensions are 128-bit non-SIMD operations.  RNDS2 has
        // an architecturally implicit third source in XMM0.
        if (!x86Handled && name.rfind("sha", 0) == 0 &&
            out.named.count("dst") && out.named.count("src")) {
            POp operation = name == "sha1msg1" ? POp::SHA1_MSG1
                              : name == "sha1msg2" ? POp::SHA1_MSG2
                              : name == "sha1nexte" ? POp::SHA1_NEXTE
                              : name == "sha1rnds4" ? POp::SHA1_RNDS4
                              : name == "sha256msg1" ? POp::SHA256_MSG1
                              : name == "sha256msg2" ? POp::SHA256_MSG2
                              : name == "sha256rnds2" ? POp::SHA256_RNDS2
                                                       : POp::UNIMPLEMENTED;
            if (operation != POp::UNIMPLEMENTED) {
                const uint64_t dstId = out.named["dst"];
                const uint64_t source = isMemory("src")
                    ? loadValue(out.named["src"], 16) : out.named["src"];
                uint64_t third = 0;
                if (operation == POp::SHA1_RNDS4)
                    third = out.named.count("imm") ? out.named["imm"] : 0;
                else if (operation == POp::SHA256_RNDS2)
                    third = x86RegVarnode(0, 16);
                uint64_t result = tmp(16);
                out.ops.push_back(PcodeOp{operation, result, dstId, source, third});
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            }
        }

        // AES-NI and VAES use the same exact 128-bit round primitive; VAES
        // simply applies it independently to every 128-bit vector lane.
        if (!x86Handled && out.named.count("dst")) {
            std::string cryptoName = name;
            const bool vectorForm = !cryptoName.empty() && cryptoName[0] == 'v';
            if (vectorForm) cryptoName.erase(cryptoName.begin());
            const bool encrypt = cryptoName == "aesenc" ||
                                 cryptoName == "aesenclast";
            const bool decrypt = cryptoName == "aesdec" ||
                                 cryptoName == "aesdeclast";
            const bool inverseMix = cryptoName == "aesimc";
            const bool keygen = cryptoName == "aeskeygenassist";
            if (encrypt || decrypt || inverseMix || keygen) {
                const uint64_t dstId = out.named["dst"];
                const Varnode* dstNode = out.find(dstId);
                const int size = dstNode && dstNode->size > 8
                                     ? dstNode->size : 16;
                uint64_t first = dstId, second = 0;
                POp operation = encrypt ? POp::AES_ENC
                                   : decrypt ? POp::AES_DEC
                                   : inverseMix ? POp::AES_IMC
                                                : POp::AES_KEYGEN;
                if (vectorForm && out.named.count("src1") &&
                    out.named.count("src2")) {
                    first = out.named["src1"];
                    second = isMemory("src2")
                                 ? loadValue(out.named["src2"], size)
                                 : out.named["src2"];
                } else if (out.named.count("src")) {
                    const uint64_t source = isMemory("src")
                                                ? loadValue(out.named["src"], size)
                                                : out.named["src"];
                    if (inverseMix || keygen) first = source;
                    else second = source;
                }
                if (keygen && out.named.count("imm")) second = out.named["imm"];
                if (first && (second || inverseMix)) {
                    uint64_t result = tmp(size);
                    const bool last = cryptoName == "aesenclast" ||
                                      cryptoName == "aesdeclast";
                    out.ops.push_back(PcodeOp{operation, result, first, second,
                                              0,
                                              static_cast<uint16_t>(last ? 1 : 0)});
                    if (vectorForm)
                        result = applyEvexMask(result, dstId, size, 128);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }
        }

        // Common scalar SSE conversion families.  Keeping these as typed
        // p-code operations preserves their signedness, IEEE width, rounding
        // mode (rounded vs CVTT truncation), and legacy upper-lane behavior.
        if (!x86Handled && out.named.count("dst")) {
            std::string laneName = name;
            const bool vexVector = !laneName.empty() && laneName[0] == 'v';
            if (vexVector) laneName.erase(laneName.begin());
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int vectorSize = dstNode && dstNode->size > 8
                                       ? dstNode->size : 16;
            auto binaryInputs = [&](uint64_t& lhs, uint64_t& rhs) {
                lhs = dstId;
                rhs = 0;
                if (vexVector && out.named.count("src1") &&
                    out.named.count("src2")) {
                    lhs = out.named["src1"];
                    rhs = isMemory("src2")
                              ? loadValue(out.named["src2"], vectorSize)
                              : out.named["src2"];
                } else if (out.named.count("src")) {
                    rhs = isMemory("src")
                              ? loadValue(out.named["src"], vectorSize)
                              : out.named["src"];
                }
                return rhs != 0;
            };
            if (!x86Handled && (laneName == "pabsb" ||
                                laneName == "pabsw" ||
                                laneName == "pabsd") &&
                out.named.count("src")) {
                const int absoluteBits = laneName.back() == 'b' ? 8
                                         : laneName.back() == 'w' ? 16 : 32;
                const uint64_t source = isMemory("src")
                                            ? loadValue(out.named["src"], vectorSize)
                                            : out.named["src"];
                uint64_t result = tmp(vectorSize);
                out.ops.push_back(PcodeOp{POp::SIMD_ABS, result, source, 0, 0,
                                          static_cast<uint16_t>(absoluteBits)});
                result = applyEvexMask(result, dstId, vectorSize, absoluteBits);
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            }

            if (!x86Handled &&
                (laneName == "phaddw" || laneName == "phaddd" ||
                 laneName == "phaddsw" || laneName == "phsubw" ||
                 laneName == "phsubd" || laneName == "phsubsw")) {
                const bool dword = laneName.back() == 'd';
                const bool subtract = laneName.rfind("phsub", 0) == 0;
                const bool saturate = laneName.find("sw") != std::string::npos;
                const int horizontalBits = dword ? 32 : 16;
                uint64_t lhs = 0, rhs = 0;
                if (binaryInputs(lhs, rhs)) {
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_INT_HORIZONTAL, result, lhs, rhs, 0,
                        static_cast<uint16_t>(horizontalBits |
                                              (subtract ? 0x0100 : 0) |
                                              (saturate ? 0x0200 : 0))});
                    result = applyEvexMask(result, dstId, vectorSize,
                                           horizontalBits);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            if (!x86Handled &&
                (laneName == "pmaddwd" || laneName == "pmaddubsw" ||
                 laneName == "pmuldq" || laneName == "pmulhrsw")) {
                const unsigned mode = laneName == "pmaddwd" ? 1
                                      : laneName == "pmaddubsw" ? 2
                                      : laneName == "pmuldq" ? 3 : 4;
                uint64_t lhs = 0, rhs = 0;
                if (binaryInputs(lhs, rhs)) {
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_MULTIPLY, result, lhs, rhs, 0,
                        static_cast<uint16_t>(mode << 8)});
                    result = applyEvexMask(result, dstId, vectorSize,
                                           mode == 3 ? 64 : mode <= 2 ?
                                           (mode == 1 ? 32 : 16) : 16);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            if (!x86Handled && (laneName == "psignb" ||
                                laneName == "psignw" ||
                                laneName == "psignd")) {
                const int signBits = laneName.back() == 'b' ? 8
                                     : laneName.back() == 'w' ? 16 : 32;
                uint64_t lhs = 0, rhs = 0;
                if (binaryInputs(lhs, rhs)) {
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{POp::SIMD_SIGN, result,
                                              lhs, rhs, 0,
                                              static_cast<uint16_t>(signBits)});
                    result = applyEvexMask(result, dstId, vectorSize, signBits);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            if (!x86Handled && laneName == "ptest") {
                uint64_t lhs = 0, rhs = 0;
                if (binaryInputs(lhs, rhs)) {
                    const uint64_t zf = tmp(1), cf = tmp(1);
                    out.ops.push_back(PcodeOp{POp::SIMD_TEST, zf, lhs, rhs, 0, 0});
                    out.ops.push_back(PcodeOp{POp::SIMD_TEST, cf, lhs, rhs, 0, 1});
                    writeFlag("ZF", zf);
                    writeFlag("CF", cf);
                    const uint64_t zero = constVarnode(out, 0, 1);
                    writeFlag("OF", zero);
                    writeFlag("SF", zero);
                    writeFlag("AF", zero);
                    writeFlag("PF", zero);
                    x86Handled = true;
                }
            }

            if (!x86Handled && (laneName == "movsldup" ||
                                laneName == "movshdup" ||
                                laneName == "movddup") &&
                out.named.count("src")) {
                const int duplicateBits = laneName == "movddup" ? 64 : 32;
                const unsigned mode = laneName == "movsldup" ? 8
                                      : laneName == "movshdup" ? 9 : 10;
                const int memorySize = laneName == "movddup" ? 8 : vectorSize;
                const uint64_t source = isMemory("src")
                                            ? loadValue(out.named["src"], memorySize)
                                            : out.named["src"];
                uint64_t result = tmp(vectorSize);
                out.ops.push_back(PcodeOp{
                    POp::SIMD_SHUFFLE, result, source, 0, 0,
                    static_cast<uint16_t>(duplicateBits | (mode << 8))});
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            }

            if (!x86Handled && (laneName == "pblendw" ||
                                laneName == "palignr") &&
                out.named.count("imm")) {
                uint64_t lhs = 0, rhs = 0;
                if (binaryInputs(lhs, rhs)) {
                    uint64_t result = tmp(vectorSize);
                    if (laneName == "pblendw") {
                        out.ops.push_back(PcodeOp{POp::SIMD_BLEND, result,
                                                  lhs, rhs, out.named["imm"], 16});
                    } else {
                        out.ops.push_back(PcodeOp{
                            POp::SIMD_SHUFFLE, result, lhs, rhs,
                            out.named["imm"],
                            static_cast<uint16_t>(8 | (7 << 8))});
                    }
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }
            int laneBits = 0;
            bool greater = false;
            if (laneName.rfind("pcmpeq", 0) == 0 ||
                laneName.rfind("pcmpgt", 0) == 0) {
                greater = laneName.rfind("pcmpgt", 0) == 0;
                const char suffix = laneName.back();
                laneBits = suffix == 'b' ? 8 : suffix == 'w' ? 16
                           : suffix == 'd' ? 32 : suffix == 'q' ? 64 : 0;
            }
            if (laneBits) {
                uint64_t lhs = 0, rhs = 0;
                if (binaryInputs(lhs, rhs)) {
                    uint64_t result = tmp(vectorSize);
                    const uint16_t aux = static_cast<uint16_t>(
                        laneBits | (greater ? 0x0100 : 0) |
                        (greater ? 0x0200 : 0));
                    out.ops.push_back(PcodeOp{POp::SIMD_COMPARE, result,
                                              lhs, rhs, 0, aux});
                    result = applyEvexMask(result, dstId, vectorSize, laneBits);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            if (!x86Handled) {
                const bool saturating = laneName == "paddsb" || laneName == "paddsw" ||
                                        laneName == "paddusb" || laneName == "paddusw" ||
                                        laneName == "psubsb" || laneName == "psubsw" ||
                                        laneName == "psubusb" || laneName == "psubusw";
                if (saturating) {
                    const bool word = laneName.back() == 'w';
                    const bool signedArithmetic = laneName.find("us") == std::string::npos;
                    const bool subtract = laneName.rfind("psub", 0) == 0;
                    laneBits = word ? 16 : 8;
                    uint64_t lhs = 0, rhs = 0;
                    if (binaryInputs(lhs, rhs)) {
                        uint64_t result = tmp(vectorSize);
                        const uint16_t aux = static_cast<uint16_t>(
                            laneBits | (signedArithmetic ? 0x0100 : 0) |
                            (subtract ? 0x0200 : 0));
                        out.ops.push_back(PcodeOp{POp::SIMD_SATURATE, result,
                                                  lhs, rhs, 0, aux});
                        result = applyEvexMask(result, dstId, vectorSize, laneBits);
                        out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                        x86Handled = true;
                    }
                }
            }

            if (!x86Handled && laneName.rfind("punpck", 0) == 0) {
                const bool high = laneName.find("punpckh") == 0;
                const std::string suffix = laneName.substr(7);
                laneBits = suffix == "bw" ? 8 : suffix == "wd" ? 16
                           : suffix == "dq" ? 32 : suffix == "qdq" ? 64 : 0;
                uint64_t lhs = 0, rhs = 0;
                if (laneBits && binaryInputs(lhs, rhs)) {
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_UNPACK, result, lhs, rhs, 0,
                        static_cast<uint16_t>(laneBits | (high ? 0x8000 : 0))});
                    result = applyEvexMask(result, dstId, vectorSize, laneBits);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            if (!x86Handled &&
                (laneName == "unpcklps" || laneName == "unpckhps" ||
                 laneName == "unpcklpd" || laneName == "unpckhpd")) {
                const bool high = laneName.find("unpckh") == 0;
                laneBits = laneName.size() >= 2 &&
                           laneName.substr(laneName.size() - 2) == "pd" ? 64 : 32;
                uint64_t lhs = 0, rhs = 0;
                if (binaryInputs(lhs, rhs)) {
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_UNPACK, result, lhs, rhs, 0,
                        static_cast<uint16_t>(laneBits |
                                              (high ? 0x8000 : 0))});
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            if (!x86Handled && (laneName == "packsswb" ||
                                laneName == "packssdw" ||
                                laneName == "packuswb" ||
                                laneName == "packusdw")) {
                laneBits = (laneName == "packssdw" || laneName == "packusdw")
                               ? 32 : 16;
                const bool unsignedDestination = laneName.rfind("packus", 0) == 0;
                uint64_t lhs = 0, rhs = 0;
                if (binaryInputs(lhs, rhs)) {
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_PACK, result, lhs, rhs, 0,
                        static_cast<uint16_t>(laneBits |
                                              (unsignedDestination ? 0x0100 : 0))});
                    result = applyEvexMask(result, dstId, vectorSize, laneBits / 2);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            if (!x86Handled && laneName == "pshufb") {
                uint64_t lhs = 0, selector = 0;
                if (binaryInputs(lhs, selector)) {
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{POp::SIMD_SHUFFLE, result,
                                              lhs, selector, 0, 0x0108});
                    result = applyEvexMask(result, dstId, vectorSize, 8);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            if (!x86Handled && out.named.count("imm") &&
                (laneName == "pshufd" || laneName == "pshuflw" ||
                 laneName == "pshufhw" || laneName == "shufps" ||
                 laneName == "shufpd")) {
                const bool binary = laneName == "shufps" || laneName == "shufpd";
                laneBits = laneName == "pshufd" ? 32
                           : laneName == "shufps" ? 32
                           : laneName == "shufpd" ? 64 : 16;
                const unsigned mode = laneName == "pshufd" ? 2
                                      : laneName == "pshuflw" ? 3
                                      : laneName == "pshufhw" ? 4
                                      : laneName == "shufps" ? 5 : 6;
                uint64_t lhs = dstId;
                uint64_t rhsOrImmediate = out.named["imm"];
                uint64_t immediate = 0;
                if (binary) {
                    uint64_t rhs = 0;
                    if (!binaryInputs(lhs, rhs)) rhs = 0;
                    rhsOrImmediate = rhs;
                    immediate = out.named["imm"];
                } else if (out.named.count("src")) {
                    lhs = isMemory("src")
                              ? loadValue(out.named["src"], vectorSize)
                              : out.named["src"];
                } else if (vexVector && out.named.count("src1")) {
                    lhs = out.named["src1"];
                }
                if (lhs && rhsOrImmediate) {
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_SHUFFLE, result, lhs, rhsOrImmediate,
                        immediate,
                        static_cast<uint16_t>(laneBits | (mode << 8))});
                    result = applyEvexMask(result, dstId, vectorSize, laneBits);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            if (!x86Handled && out.named.count("imm")) {
                if (laneName == "pslldq" || laneName == "psrldq") {
                    const uint64_t source = vexVector && out.named.count("src")
                                                ? out.named["src"] : dstId;
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_BYTE_SHIFT, result, source,
                        out.named["imm"], 0,
                        static_cast<uint16_t>(laneName == "psrldq" ? 1 : 0)});
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
                bool shift = false, right = false, arithmetic = false;
                if (laneName == "psllw" || laneName == "pslld" ||
                    laneName == "psllq") shift = true;
                else if (laneName == "psrlw" || laneName == "psrld" ||
                         laneName == "psrlq") { shift = true; right = true; }
                else if (laneName == "psraw" || laneName == "psrad") {
                    shift = true; right = true; arithmetic = true;
                }
                if (shift) {
                    laneBits = laneName.back() == 'w' ? 16
                               : laneName.back() == 'd' ? 32 : 64;
                    const uint64_t source = vexVector && out.named.count("src1")
                                                ? out.named["src1"] : dstId;
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_SHIFT, result, source, out.named["imm"], 0,
                        static_cast<uint16_t>(laneBits | (right ? 0x0100 : 0) |
                                              (arithmetic ? 0x0200 : 0))});
                    result = applyEvexMask(result, dstId, vectorSize, laneBits);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            if (!x86Handled && out.named.count("src")) {
                bool shift = false, right = false, arithmetic = false;
                if (laneName == "psllw" || laneName == "pslld" ||
                    laneName == "psllq") shift = true;
                else if (laneName == "psrlw" || laneName == "psrld" ||
                         laneName == "psrlq") { shift = true; right = true; }
                else if (laneName == "psraw" || laneName == "psrad") {
                    shift = true; right = true; arithmetic = true;
                }
                if (shift) {
                    laneBits = laneName.back() == 'w' ? 16
                               : laneName.back() == 'd' ? 32 : 64;
                    const uint64_t count = isMemory("src")
                                               ? loadValue(out.named["src"], 16)
                                               : out.named["src"];
                    uint64_t result = tmp(vectorSize);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_SHIFT, result, dstId, count, 0,
                        static_cast<uint16_t>(laneBits | (right ? 0x0100 : 0) |
                                              (arithmetic ? 0x0200 : 0))});
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

        }

        if (!x86Handled &&
            (name == "pcmpistri" || name == "pcmpistrm" ||
             name == "pcmpestri" || name == "pcmpestrm") &&
            out.named.count("dst") && out.named.count("src") &&
            out.named.count("imm")) {
            const bool explicitLengths = name.find("estr") != std::string::npos;
            const bool maskResult = name.back() == 'm';
            const Varnode* immediateNode = out.find(out.named["imm"]);
            const unsigned control = immediateNode
                ? static_cast<unsigned>(immediateNode->offset & 0xffU) : 0;
            const uint64_t left = out.named["dst"];
            const uint64_t right = isMemory("src")
                                       ? loadValue(out.named["src"], 16)
                                       : out.named["src"];
            uint64_t lengths = 0;
            if (explicitLengths) {
                lengths = tmp(8);
                out.ops.push_back(PcodeOp{POp::PIECE, lengths,
                                          x86RegVarnode(2, 4),
                                          x86RegVarnode(0, 4), 0});
            }
            auto compareQuery = [&](unsigned query, int size) {
                const uint64_t result = tmp(size);
                const uint16_t aux = static_cast<uint16_t>(
                    control | (query << 8) | (explicitLengths ? 0x0800 : 0));
                out.ops.push_back(PcodeOp{POp::SIMD_STRING_COMPARE, result,
                                          left, right, lengths, aux});
                return result;
            };
            if (maskResult) {
                const uint64_t bits = compareQuery(0, 8);
                const uint64_t mask = tmp(16);
                out.ops.push_back(PcodeOp{POp::SIMD_STRING_MASK, mask,
                                          bits, 0, 0,
                                          static_cast<uint16_t>(control)});
                out.ops.push_back(PcodeOp{POp::COPY, x86RegVarnode(0, 16),
                                          mask, 0, 0});
            } else {
                out.ops.push_back(PcodeOp{POp::COPY, x86RegVarnode(1, 4),
                                          compareQuery(1, 4), 0, 0});
            }
            writeFlag("CF", compareQuery(2, 1));
            writeFlag("ZF", compareQuery(3, 1));
            writeFlag("SF", compareQuery(4, 1));
            writeFlag("OF", compareQuery(5, 1));
            const uint64_t zero = constVarnode(out, 0, 1);
            writeFlag("AF", zero);
            writeFlag("PF", zero);
            x86Handled = true;
        }

        if (!x86Handled && out.named.count("dst")) {
            std::string approximateName = name;
            if (!approximateName.empty() && approximateName[0] == 'v')
                approximateName.erase(approximateName.begin());
            const bool reciprocal = approximateName == "rcpps" ||
                                    approximateName == "rcpss";
            const bool reciprocalSqrt = approximateName == "rsqrtps" ||
                                        approximateName == "rsqrtss";
            if (reciprocal || reciprocalSqrt) {
                const bool scalar = approximateName.size() >= 2 &&
                                    approximateName.substr(
                                        approximateName.size() - 2) == "ss";
                const bool vexForm = name[0] == 'v';
                const std::string sourceOperand = vexForm && out.named.count("src2")
                                                      ? "src2" : "src";
                if (out.named.count(sourceOperand)) {
                    const uint64_t dstId = out.named["dst"];
                    const Varnode* dstNode = out.find(dstId);
                    const int size = dstNode && dstNode->size > 8
                                         ? dstNode->size : 16;
                    const uint64_t source = isMemory(sourceOperand)
                        ? loadValue(out.named[sourceOperand], scalar ? 4 : size)
                        : out.named[sourceOperand];
                    const uint64_t base = vexForm && out.named.count("src1")
                                              ? out.named["src1"] : dstId;
                    const uint64_t result = tmp(size);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_APPROX, result, source, base, 0,
                        static_cast<uint16_t>(32 |
                            (reciprocalSqrt ? 0x0100 : 0) |
                            (scalar ? 0x8000 : 0))});
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }
        }

        if (!x86Handled && name.rfind("pmov", 0) == 0 &&
            (name.rfind("pmovsx", 0) == 0 || name.rfind("pmovzx", 0) == 0) &&
            out.named.count("dst") && out.named.count("src")) {
            const bool signedExtend = name.rfind("pmovsx", 0) == 0;
            const std::string widths = name.substr(6);
            auto width = [](char suffix) {
                return suffix == 'b' ? 8 : suffix == 'w' ? 16
                       : suffix == 'd' ? 32 : suffix == 'q' ? 64 : 0;
            };
            const int sourceBits = widths.size() == 2 ? width(widths[0]) : 0;
            const int destinationBits = widths.size() == 2 ? width(widths[1]) : 0;
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size > 8 ? dstNode->size : 16;
            if (sourceBits && destinationBits > sourceBits) {
                const int sourceSize = size / (destinationBits / 8) *
                                       (sourceBits / 8);
                const uint64_t source = isMemory("src")
                                            ? loadValue(out.named["src"], sourceSize)
                                            : out.named["src"];
                const uint64_t result = tmp(size);
                const uint16_t aux = static_cast<uint16_t>(
                    sourceBits | (destinationBits << 8) |
                    (signedExtend ? 0x8000 : 0));
                out.ops.push_back(PcodeOp{POp::SIMD_EXTEND, result,
                                          source, 0, 0, aux});
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            }
        }

        if (!x86Handled && out.named.count("dst") && out.named.count("imm")) {
            std::string roundName = name;
            if (!roundName.empty() && roundName[0] == 'v')
                roundName.erase(roundName.begin());
            const bool round32 = roundName == "roundps" || roundName == "roundss";
            const bool round64 = roundName == "roundpd" || roundName == "roundsd";
            if (round32 || round64) {
                const bool scalar = roundName == "roundss" || roundName == "roundsd";
                const bool vexForm = name[0] == 'v';
                const std::string sourceOperand = vexForm && out.named.count("src2")
                                                      ? "src2" : "src";
                if (out.named.count(sourceOperand)) {
                    const uint64_t dstId = out.named["dst"];
                    const Varnode* dstNode = out.find(dstId);
                    const int size = dstNode && dstNode->size > 8
                                         ? dstNode->size : 16;
                    const int laneBits = round32 ? 32 : 64;
                    const uint64_t source = isMemory(sourceOperand)
                        ? loadValue(out.named[sourceOperand],
                                    scalar ? laneBits / 8 : size)
                        : out.named[sourceOperand];
                    const uint64_t base = vexForm && out.named.count("src1")
                                              ? out.named["src1"] : dstId;
                    const uint64_t result = tmp(size);
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_ROUND, result, source, base,
                        out.named["imm"],
                        static_cast<uint16_t>(laneBits |
                                              (scalar ? 0x8000 : 0))});
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }
        }

        if (!x86Handled && out.named.count("dst") && out.named.count("src")) {
            const bool packedIntToFloat = name == "cvtdq2ps" ||
                                          name == "cvtdq2pd";
            const bool packedFloatToInt = name == "cvtps2dq" ||
                                          name == "cvttps2dq" ||
                                          name == "cvtpd2dq" ||
                                          name == "cvttpd2dq";
            const bool packedFloatToFloat = name == "cvtps2pd" ||
                                            name == "cvtpd2ps";
            if (packedIntToFloat || packedFloatToInt || packedFloatToFloat) {
                const uint64_t dstId = out.named["dst"];
                const Varnode* dstNode = out.find(dstId);
                const int destinationSize = dstNode && dstNode->size > 8
                                                ? dstNode->size : 16;
                int sourceBits = 32, destinationBits = 32, memorySize = 16;
                POp conversion = POp::SIMD_INT2FLOAT;
                bool truncate = false;
                if (name == "cvtdq2pd") {
                    destinationBits = 64;
                    memorySize = 8;
                } else if (name == "cvtpd2dq" || name == "cvttpd2dq") {
                    conversion = POp::SIMD_FLOAT2INT;
                    sourceBits = 64;
                    memorySize = 16;
                    truncate = name == "cvttpd2dq";
                } else if (name == "cvtps2dq" || name == "cvttps2dq") {
                    conversion = POp::SIMD_FLOAT2INT;
                    truncate = name == "cvttps2dq";
                } else if (name == "cvtps2pd") {
                    conversion = POp::SIMD_FLOAT2FLOAT;
                    destinationBits = 64;
                    memorySize = 8;
                } else if (name == "cvtpd2ps") {
                    conversion = POp::SIMD_FLOAT2FLOAT;
                    sourceBits = 64;
                    memorySize = 16;
                }
                const uint64_t source = isMemory("src")
                                            ? loadValue(out.named["src"], memorySize)
                                            : out.named["src"];
                const uint64_t result = tmp(destinationSize);
                const uint16_t aux = static_cast<uint16_t>(
                    sourceBits | (destinationBits << 8) |
                    (truncate ? 0x8000 : 0));
                out.ops.push_back(PcodeOp{conversion, result, source, 0, 0, aux});
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            }
        }

        if (!x86Handled && (name == "dpps" || name == "dppd") &&
            out.named.count("dst") && out.named.count("src") &&
            out.named.count("imm")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size > 8 ? dstNode->size : 16;
            const uint64_t source = isMemory("src")
                                        ? loadValue(out.named["src"], 16)
                                        : out.named["src"];
            const uint64_t result = tmp(size);
            out.ops.push_back(PcodeOp{
                POp::SIMD_DOT_PRODUCT, result, dstId, source,
                out.named["imm"], static_cast<uint16_t>(name == "dpps" ? 32 : 64)});
            out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
            x86Handled = true;
        }

        if (!x86Handled && out.named.count("dst") && out.named.count("src")) {
            const bool intToFloat = name == "cvtsi2ss" || name == "cvtsi2sd";
            const bool floatToInt = name == "cvtss2si" || name == "cvtsd2si" ||
                                    name == "cvttss2si" || name == "cvttsd2si";
            const bool floatToFloat = name == "cvtss2sd" || name == "cvtsd2ss";
            const uint64_t dstId = out.named["dst"];
            const uint64_t srcId = out.named["src"];
            const Varnode* dstNode = out.find(dstId);
            if (intToFloat) {
                const int integerSize = xc.rexw ? 8 : 4;
                const int floatBits = name == "cvtsi2ss" ? 32 : 64;
                const int destinationSize = dstNode && dstNode->size > 8
                                                ? dstNode->size : 16;
                const uint64_t source = isMemory("src")
                                            ? loadValue(srcId, integerSize)
                                            : resized(srcId, integerSize, true);
                const uint64_t result = tmp(destinationSize);
                out.ops.push_back(PcodeOp{POp::FLOAT_INT2FLOAT, result, source,
                                          dstId, 0,
                                          static_cast<uint16_t>(floatBits)});
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            } else if (floatToInt) {
                const bool single = name.find("ss2si") != std::string::npos;
                const bool truncate = name.rfind("cvtt", 0) == 0;
                const int floatBits = single ? 32 : 64;
                const int integerSize = xc.rexw ? 8 : 4;
                const uint64_t source = isMemory("src")
                                            ? loadValue(srcId, floatBits / 8)
                                            : srcId;
                const uint64_t result = tmp(integerSize);
                const uint16_t aux = static_cast<uint16_t>(
                    floatBits | (truncate ? 0x8000 : 0));
                out.ops.push_back(PcodeOp{POp::FLOAT_FLOAT2INT, result, source,
                                          0, 0, aux});
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            } else if (floatToFloat) {
                const int sourceBits = name == "cvtss2sd" ? 32 : 64;
                const int destinationBits = name == "cvtss2sd" ? 64 : 32;
                const int destinationSize = dstNode && dstNode->size > 8
                                                ? dstNode->size : 16;
                const uint64_t source = isMemory("src")
                                            ? loadValue(srcId, sourceBits / 8)
                                            : srcId;
                const uint64_t result = tmp(destinationSize);
                const uint16_t aux = static_cast<uint16_t>(sourceBits |
                                                           (destinationBits << 8));
                out.ops.push_back(PcodeOp{POp::FLOAT_FLOAT2FLOAT, result,
                                          source, dstId, 0, aux});
                out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                x86Handled = true;
            }
        }

        // Scalar and packed IEEE-754 semantics for the common SSE/AVX
        // arithmetic families.  aux stores lane width and the scalar marker.
        if (!x86Handled && out.named.count("dst")) {
            std::string floatName = name;
            const bool vexForm = !floatName.empty() && floatName[0] == 'v';
            if (vexForm) floatName.erase(floatName.begin());
            const bool f32 = floatName.size() >= 2 &&
                             (floatName.substr(floatName.size() - 2) == "ps" ||
                              floatName.substr(floatName.size() - 2) == "ss");
            const bool f64 = floatName.size() >= 2 &&
                             (floatName.substr(floatName.size() - 2) == "pd" ||
                              floatName.substr(floatName.size() - 2) == "sd");
            const bool scalar = floatName.size() >= 2 &&
                                (floatName.substr(floatName.size() - 2) == "ss" ||
                                 floatName.substr(floatName.size() - 2) == "sd");
            const std::string stem = (f32 || f64)
                                         ? floatName.substr(0, floatName.size() - 2)
                                         : std::string();
            POp floatOp = POp::UNIMPLEMENTED;
            if (stem == "add") floatOp = POp::FLOAT_ADD;
            else if (stem == "sub") floatOp = POp::FLOAT_SUB;
            else if (stem == "mul") floatOp = POp::FLOAT_MULT;
            else if (stem == "div") floatOp = POp::FLOAT_DIV;
            else if (stem == "sqrt") floatOp = POp::FLOAT_SQRT;
            else if (stem == "min") floatOp = POp::FLOAT_MIN;
            else if (stem == "max") floatOp = POp::FLOAT_MAX;
            if ((f32 || f64) && floatOp != POp::UNIMPLEMENTED) {
                const uint64_t dstId = out.named["dst"];
                const Varnode* dstNode = out.find(dstId);
                const int size = dstNode && dstNode->size ? dstNode->size : 16;
                const int laneBits = f32 ? 32 : 64;
                const uint16_t aux = static_cast<uint16_t>(laneBits |
                                                           (scalar ? 0x8000 : 0));
                auto sourceValue = [&](const std::string& operand, int loadSize) {
                    const uint64_t id = out.named[operand];
                    return isMemory(operand) ? loadValue(id, loadSize) : id;
                };
                uint64_t a = dstId, b = 0;
                if (floatOp == POp::FLOAT_SQRT) {
                    const std::string source = vexForm && out.named.count("src2")
                                                   ? "src2" : "src";
                    if (out.named.count(source))
                        a = sourceValue(source, scalar ? laneBits / 8 : size);
                    b = vexForm && out.named.count("src1") ? out.named["src1"] : dstId;
                } else if (vexForm && out.named.count("src1") &&
                           out.named.count("src2")) {
                    a = out.named["src1"];
                    b = sourceValue("src2", scalar ? laneBits / 8 : size);
                } else if (out.named.count("src")) {
                    a = dstId;
                    b = sourceValue("src", scalar ? laneBits / 8 : size);
                }
                if (a && (b || floatOp == POp::FLOAT_SQRT)) {
                    uint64_t result = tmp(size);
                    out.ops.push_back(PcodeOp{floatOp, result, a, b, 0, aux});
                    result = applyEvexMask(result, dstId, size, laneBits);
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }

            const bool compare = floatName == "comiss" || floatName == "ucomiss" ||
                                 floatName == "comisd" || floatName == "ucomisd";
            if (!x86Handled && compare) {
                const bool compare32 = floatName.size() >= 2 &&
                                       floatName.substr(floatName.size() - 2) == "ss";
                const uint16_t aux = static_cast<uint16_t>(compare32 ? 32 : 64);
                const uint64_t lhs = out.named["dst"];
                std::string rhsName = out.named.count("src2") ? "src2" : "src";
                if (out.named.count(rhsName)) {
                    const uint64_t rhsId = out.named[rhsName];
                    const uint64_t rhs = isMemory(rhsName)
                                             ? loadValue(rhsId, compare32 ? 4 : 8)
                                             : rhsId;
                    out.ops.push_back(PcodeOp{
                        POp::SIMD_COMPARE_CHECK, 0, lhs, rhs, 0,
                        static_cast<uint16_t>(aux |
                            ((floatName.rfind("ucom", 0) == 0) ? 0x0100 : 0))});
                    auto emitFloatCompare = [&](POp op) {
                        const uint64_t result = tmp(1);
                        out.ops.push_back(PcodeOp{op, result, lhs, rhs, 0, aux});
                        return result;
                    };
                    const uint64_t unordered = emitFloatCompare(POp::FLOAT_NAN);
                    const uint64_t less = emitFloatCompare(POp::FLOAT_LESS);
                    const uint64_t equal = emitFloatCompare(POp::FLOAT_EQUAL);
                    writeFlag("CF", emit2(POp::INT_OR, unordered, less, 1));
                    writeFlag("PF", unordered);
                    writeFlag("ZF", emit2(POp::INT_OR, unordered, equal, 1));
                    const uint64_t zero = constVarnode(out, 0, 1);
                    writeFlag("OF", zero); writeFlag("SF", zero); writeFlag("AF", zero);
                    x86Handled = true;
                }
            }
        }

        if (!x86Handled && name.rfind("cmov", 0) == 0 &&
            out.named.count("dst") && out.named.count("src")) {
            const uint64_t dstId = out.named["dst"];
            const Varnode* dstNode = out.find(dstId);
            const int size = dstNode && dstNode->size ? dstNode->size : xc.opsz;
            const uint64_t srcId = out.named["src"];
            const uint64_t src = isMemory("src") ? loadValue(srcId, size)
                                                   : resized(srcId, size, false);
            const uint64_t selected = emitSelect(condition(name.substr(4)), src,
                                                 resized(dstId, size, false), size);
            out.ops.push_back(PcodeOp{POp::COPY, dstId, selected, 0, 0});
            x86Handled = true;
        }
    }

    // emit semantics not replaced by the shared x86 flag implementation
    // Memory operands bound by the pattern carry their address as a CONST
    // varnode; a memory goto/call destination must load the pointer stored
    // at that address (indirect), not branch to the address itself.
    auto stmtIsMemory = [&](const std::string& operand) {
        for (auto it = magicExports.rbegin(); it != magicExports.rend(); ++it)
            if (it->first == operand)
                return it->second.rfind("rmmem", 0) == 0;
        return false;
    };
    auto stmtLoadValue = [&](uint64_t address, int size) {
        Varnode* t = makeVarnode(out, Varnode::UNIQUE, nextId_++, size);
        out.ops.push_back(PcodeOp{POp::LOAD, t->id, address, 0, 0});
        return t->id;
    };
    if (!x86Handled) for (const auto& st : matched->stmts) {
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
            // A memory destination (`jmp m64`) is an indirect branch through
            // the pointer stored at the operand address, not a branch to the
            // address itself; register destinations use the register value.
            if (st.rhsE && st.rhsE->kind == SpecCtor::SExpr::VAR &&
                stmtIsMemory(st.rhsE->var)) {
                const uint64_t addr = evalExpr(out, *st.rhsE);
                const uint64_t dest = stmtLoadValue(addr, 8);
                out.ops.push_back(PcodeOp{POp::BRANCHIND, 0, dest, 0, 0});
                break;
            }
            const uint64_t dest = evalExpr(out, *st.rhsE);
            const Varnode* target = out.find(dest);
            out.ops.push_back(PcodeOp{target && target->isConst()
                                          ? POp::BRANCH : POp::BRANCHIND,
                                      0, dest, 0, 0});
            break;
        }
        case SpecCtor::SStmt::CGOTO: {
            const uint64_t cond = evalExpr(out, *st.condE);
            const uint64_t dest = evalExpr(out, *st.rhsE);
            out.ops.push_back(PcodeOp{POp::CBRANCH, 0, dest, cond, 0});
            break;
        }
        case SpecCtor::SStmt::CALL: {
            if (st.rhsE && st.rhsE->kind == SpecCtor::SExpr::VAR &&
                stmtIsMemory(st.rhsE->var)) {
                const uint64_t addr = evalExpr(out, *st.rhsE);
                const uint64_t dest = stmtLoadValue(addr, 8);
                out.ops.push_back(PcodeOp{POp::CALLIND, 0, dest, 0, 0});
                break;
            }
            const uint64_t dest = evalExpr(out, *st.rhsE);
            const Varnode* target = out.find(dest);
            out.ops.push_back(PcodeOp{target && target->isConst()
                                          ? POp::CALL : POp::CALLIND,
                                      0, dest, 0, 0});
            break;
        }
        case SpecCtor::SStmt::RET:
            out.ops.push_back(PcodeOp{POp::RETURN, 0, 0, 0, 0});
            break;
        case SpecCtor::SStmt::STORE: {
            const uint64_t addrId = evalExpr(out, *st.lhsE);
            uint64_t valId = evalExpr(out, *st.rhsE);
            if (archX86_) {
                // A STORE has no output varnode from which later stages can
                // recover its width.  In particular, sext(imm16, 16) is held
                // in an eight-byte temporary, but `66 C7 /0 iw` still writes
                // exactly two bytes.  Preserve the decoded memory operand
                // width here so adjacent C++ object fields are not clobbered.
                int width = st.storeSize;
                if (!width && st.lhsE && st.lhsE->kind == SpecCtor::SExpr::VAR) {
                    for (auto it = magicExports.rbegin();
                         it != magicExports.rend(); ++it) {
                        if (it->first == st.lhsE->var &&
                            it->second.rfind("rmmem", 0) == 0) {
                            width = magicSize(it->second);
                            break;
                        }
                    }
                }
                const Varnode* value = out.find(valId);
                if (!width && value) width = value->size;
                if (width > 0 && value && value->size != width) {
                    if (value->isConst()) {
                        valId = constVarnode(out, value->offset, width);
                    } else {
                        Varnode* resized = makeVarnode(
                            out, Varnode::UNIQUE, nextId_++, width);
                        out.ops.push_back(PcodeOp{
                            value->size > width ? POp::SUBPIECE
                                                : POp::INT_ZEXT,
                            resized->id, valId, 0, 0});
                        valId = resized->id;
                    }
                }
            }
            out.ops.push_back(PcodeOp{POp::STORE, 0, addrId, 0, valId});
            break;
        }
        }
    }

    if (archX86_) {
        const std::string& instruction = matched->name;
        uint16_t gate = 0;
        uint16_t feature = 0;
        static const std::set<std::string> privileged = {
            "hlt", "invlpg", "invpcid", "lgdt", "lidt",
            "lldt", "ltr", "movcr", "rdmsr", "wrmsr", "xsetbv",
            "clts", "swapgs", "invd", "wbinvd"
        };
        if (privileged.count(instruction)) gate = 1;
        if (instruction == "cli" || instruction == "sti" ||
            instruction == "in" || instruction == "out") gate = 7;
        if (!instruction.empty() && instruction[0] == 'f')
            gate = instruction.rfind("fn", 0) == 0 ? 5 : 2;
        if (instruction == "wait") gate = 6;
        if (instruction.rfind("sha", 0) == 0) { gate = 3; feature = 1; }
        if (instruction.find("gf2p8") != std::string::npos) {
            gate = xc.vex || xc.evex ? 4 : 3; feature = 2;
        }
        if (instruction.find("aes") != std::string::npos) {
            gate = xc.vex || xc.evex ? 4 : 3; feature = 3;
        }
        if (instruction.find("clmul") != std::string::npos) {
            gate = xc.vex || xc.evex ? 4 : 3; feature = 4;
        }
        if (gate || feature)
            out.ops.insert(out.ops.begin(), PcodeOp{
                POp::X86_GUARD, 0, 0, 0, 0,
                static_cast<uint16_t>(gate | (feature << 8))});
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
        case POp::CALLIND:
            out.kind = Insn::CALL;
            if (constDest) {
                out.target = vd->offset;
                out.targetKnown = true;
            }
            break;
        case POp::BRANCH:
        case POp::BRANCHIND:
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
        if (!v->name.empty()) return v->name;
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
    if (getenv("CF_DBG_CTOR"))
        std::fprintf(stderr, "[dbg] ctor=%s mod=%d reg=%d rm=%d base=%d isMem=%d rexw=%d rexb=%d\n",
                    matched->name.c_str(), xc.mod, xc.reg, xc.rm, xc.base, xc.isMem, xc.rexw, xc.rexb);
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
    cache_ = nullptr;
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

} // namespace centrifuge
