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
               (n == "rregv" || n == "rmregv" || n.rfind("acc", 0) == 0 ||
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
            std::snprintf(b, sizeof(b), "[0x%llx]",
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
        if (mname == "rregv" || mname == "rmregv") {
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
            if (mname.size() > 5 && xc.mod == 1) {
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
            return emit1(signExtend ? POp::INT_SEXT : POp::INT_ZEXT, id, size);
        };
        auto loadValue = [&](uint64_t address, int size) {
            const uint64_t r = tmp(size);
            out.ops.push_back(PcodeOp{POp::LOAD, r, address, 0, 0});
            return r;
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
        const std::set<std::string> arithmetic = {
            "add", "adc", "sub", "sbb", "cmp", "and", "or", "xor",
            "test", "inc", "dec", "neg", "xadd"
        };
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

        // Full-width aligned/unaligned SIMD moves.  Store encodings reverse
        // the ModRM roles relative to load encodings, so use the opcode rather
        // than the constructor's display operand names.
        if (!x86Handled && out.named.count("dst") && out.named.count("src")) {
            std::string moveName = name;
            if (!moveName.empty() && moveName[0] == 'v') moveName.erase(moveName.begin());
            const std::set<std::string> vectorMoves = {
                "movups", "movupd", "movaps", "movapd", "movdqa", "movdqu"
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
                if (storeEncoding) {
                    if (isMemory("src"))
                        out.ops.push_back(PcodeOp{POp::STORE, 0, srcId, 0, dstId});
                    else
                        out.ops.push_back(PcodeOp{POp::COPY, srcId, dstId, 0, 0});
                } else {
                    const uint64_t value = isMemory("src") ? loadValue(srcId, size) : srcId;
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, value, 0, 0});
                }
                x86Handled = true;
            }
        }

        // Packed bitwise and wrapping integer lane operations.
        if (!x86Handled && out.named.count("dst")) {
            std::string vectorName = name;
            const bool vexVector = !vectorName.empty() && vectorName[0] == 'v';
            if (vexVector) vectorName.erase(vectorName.begin());
            POp vectorOp = POp::UNIMPLEMENTED;
            int laneBits = 0;
            if (vectorName == "andps" || vectorName == "andpd" ||
                vectorName == "pand" || vectorName == "pandd" || vectorName == "pandq")
                vectorOp = POp::INT_AND;
            else if (vectorName == "orps" || vectorName == "orpd" ||
                     vectorName == "por")
                vectorOp = POp::INT_OR;
            else if (vectorName == "xorps" || vectorName == "xorpd" ||
                     vectorName == "pxor")
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
                    const uint64_t result = tmp(size);
                    out.ops.push_back(PcodeOp{vectorOp, result, a, b, 0,
                                              static_cast<uint16_t>(laneBits)});
                    out.ops.push_back(PcodeOp{POp::COPY, dstId, result, 0, 0});
                    x86Handled = true;
                }
            }
        }

        // Common scalar SSE conversion families.  Keeping these as typed
        // p-code operations preserves their signedness, IEEE width, rounding
        // mode (rounded vs CVTT truncation), and legacy upper-lane behavior.
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
                    const uint64_t result = tmp(size);
                    out.ops.push_back(PcodeOp{floatOp, result, a, b, 0, aux});
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
