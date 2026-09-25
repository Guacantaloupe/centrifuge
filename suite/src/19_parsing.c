/* 19. Parsing family. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(pa_parse_uint);
uint64_t pa_parse_uint(const char *s) {
    MARK(pa_parse_uint);
    uint64_t v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10 + (uint64_t)(*s++ - '0');
    return v;
}
TAG(pa_parse_int);
int64_t pa_parse_int(const char *s) {
    MARK(pa_parse_int);
    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    int64_t v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    return neg ? -v : v;
}
TAG(pa_parse_hex);
uint64_t pa_parse_hex(const char *s) {
    MARK(pa_parse_hex);
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    uint64_t v = 0;
    for (;;) {
        unsigned c = (unsigned char)*s;
        unsigned d = c >= '0' && c <= '9' ? c - '0'
                   : c >= 'a' && c <= 'f' ? c - 'a' + 10
                   : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 99;
        if (d > 15) break;
        v = v * 16 + d;
        s++;
    }
    return v;
}
TAG(pa_overflow_check);
int pa_overflow_check(const char *s, uint64_t *out) {
    MARK(pa_overflow_check);
    uint64_t v = 0;
    while (*s >= '0' && *s <= '9') {
        unsigned d = (unsigned)(*s++ - '0');
        if (v > (UINT64_MAX - d) / 10) return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}
/* recursive-descent expression parser: expr -> term {+ term}, term -> factor {* factor} */
static const char *g_cursor;
static int rd_expr(void);
static int rd_factor(void) {
    if (*g_cursor == '(') {
        g_cursor++;
        int v = rd_expr();
        if (*g_cursor == ')') g_cursor++;
        return v;
    }
    int v = 0;
    while (*g_cursor >= '0' && *g_cursor <= '9') v = v * 10 + (*g_cursor++ - '0');
    return v;
}
static int rd_term(void) {
    int v = rd_factor();
    while (*g_cursor == '*') { g_cursor++; v *= rd_factor(); }
    return v;
}
static int rd_expr(void) {
    int v = rd_term();
    while (*g_cursor == '+') { g_cursor++; v += rd_term(); }
    return v;
}
TAG(pa_recursive_descent);
int pa_recursive_descent(const char *expr) {
    MARK(pa_recursive_descent);
    g_cursor = expr;
    return rd_expr();
}
/* shunting-yard */
TAG(pa_shunting_yard);
int pa_shunting_yard(const char *in, char *out) {
    MARK(pa_shunting_yard);
    char st[32];
    int sp = 0, k = 0;
    for (const char *p = in; *p; p++) {
        if (*p >= '0' && *p <= '9') out[k++] = *p;
        else if (*p == '*' || *p == '/') {
            while (sp && (st[sp - 1] == '*' || st[sp - 1] == '/')) out[k++] = st[--sp];
            st[sp++] = *p;
        } else if (*p == '+' || *p == '-') {
            while (sp && st[sp - 1] != '(') out[k++] = st[--sp];
            st[sp++] = *p;
        } else if (*p == '(') st[sp++] = *p;
        else if (*p == ')') {
            while (sp && st[sp - 1] != '(') out[k++] = st[--sp];
            if (sp) sp--;
        }
    }
    while (sp) out[k++] = st[--sp];
    out[k] = 0;
    return k;
}
/* lexer: switch-based */
enum tok { T_NUM, T_ID, T_OP, T_EOF, T_ERR };
struct token { enum tok kind; int val; };
TAG(pa_lexer_switch);
struct token pa_lexer_switch(const char **pp) {
    MARK(pa_lexer_switch);
    const char *p = *pp;
    while (*p == ' ' || *p == '\t') p++;
    struct token t = { T_EOF, 0 };
    if (!*p) { *pp = p; return t; }
    if (*p >= '0' && *p <= '9') {
        t.kind = T_NUM;
        while (*p >= '0' && *p <= '9') t.val = t.val * 10 + (*p++ - '0');
    } else if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')) {
        t.kind = T_ID;
        t.val = *p++;
    } else switch (*p) {
        case '+': case '-': case '*': case '/': t.kind = T_OP; t.val = *p++; break;
        default: t.kind = T_ERR; p++; break;
    }
    *pp = p;
    return t;
}
/* lexer: table-driven DFA over char classes */
static int char_class(unsigned char c) {
    if (c >= '0' && c <= '9') return 0;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') return 1;
    if (c == ' ' || c == '\t' || c == '\n') return 2;
    if (c == '+') return 3;
    if (c == '=') return 4;
    return 5;
}
TAG(pa_lexer_dfa);
int pa_lexer_dfa(const char *s) {
    MARK(pa_lexer_dfa);
    /* transition table: state x class -> next state (0 = reject) */
    static const int trans[5][6] = {
        { 2, 3, 1, 4, 5, 0 },   /* 1 = skip/space */
        { 2, 0, 0, 0, 0, 0 },   /* 2 = number */
        { 3, 3, 0, 0, 0, 0 },   /* 3 = ident */
        { 0, 0, 0, 0, 5, 0 },   /* 4 = op, maybe == */
        { 0, 0, 0, 0, 0, 0 },   /* 5 = done token */
    };
    int count = 0;
    while (*s) {
        int state = 1;
        do {
            state = trans[state - 1][char_class((unsigned char)*s)];
            if (state) s++;
        } while (state && state != 5 && state != 2 && state != 3);
        if (state == 2 || state == 3 || state == 5 || state == 4) count++;
        else if (!state) { count = -count; break; }
    }
    return count;
}
/* tiny JSON value skipper (no allocation) */
TAG(pa_json_skip);
int pa_json_skip(const char **pp) {
    MARK(pa_json_skip);
    const char *p = *pp;
    while (*p == ' ' || *p == '\t' || *p == '\n') p++;
    if (*p == '{' || *p == '[') {
        char open = *p++, close = open == '{' ? '}' : ']';
        int depth = 1;
        while (*p && depth) {
            if (*p == open) depth++;
            else if (*p == close) depth--;
            else if (*p == '"') { p++; while (*p && *p != '"') p++; }
            p++;
        }
        *pp = p;
        return depth == 0 ? 0 : -1;
    }
    if (*p == '"') { p++; while (*p && *p != '"') p++; if (*p) p++; *pp = p; return 0; }
    while (*p && (*p >= '0' && *p <= '9' || *p == '-' || *p == '.' ||
                   *p == 'e' || *p == 'E' || *p == '+')) p++;
    *pp = p;
    return 0;
}
/* CSV field copy */
TAG(pa_csv_field);
int pa_csv_field(const char **pp, char *out, int cap) {
    MARK(pa_csv_field);
    const char *p = *pp;
    int k = 0, quoted = *p == '"';
    if (quoted) p++;
    while (*p && k < cap - 1) {
        if (quoted && *p == '"') { p++; break; }
        if (!quoted && (*p == ',' || *p == '\n')) break;
        if (*p == '"' && p[1] == '"') { out[k++] = '"'; p += 2; continue; }
        out[k++] = *p++;
    }
    out[k] = 0;
    while (*p && *p != ',' && *p != '\n') p++;
    if (*p == ',') p++;
    *pp = p;
    return k;
}
/* INI: [section] / key=value line classifier */
TAG(pa_ini_line);
int pa_ini_line(const char *line, char *key, char *val) {
    MARK(pa_ini_line);
    while (*line == ' ' || *line == '\t') line++;
    if (!*line || *line == ';' || *line == '#') return 0;
    if (*line == '[') return 1;
    int k = 0;
    while (*line && *line != '=' && *line != ' ' && k < 31)
        key[k++] = *line++;
    key[k] = 0;
    while (*line == ' ') line++;
    if (*line != '=') return -1;
    line++;
    while (*line == ' ') line++;
    int v = 0;
    while (*line && *line != '\n' && *line != ';' && v < 31)
        val[v++] = *line++;
    val[v] = 0;
    return 2;
}
/* bytecode interpreter loop */
TAG(pa_bytecode_vm);
int pa_bytecode_vm(const int *code, int n) {
    MARK(pa_bytecode_vm);
    int st[16], sp = 0, pc = 0;
    while (pc < n) {
        int op = code[pc++];
        switch (op) {
            case 0: st[sp++] = code[pc++]; break;              /* push */
            case 1: sp--; break;                               /* pop */
            case 2: st[sp - 2] = st[sp - 2] + st[sp - 1]; sp--; break;
            case 3: st[sp - 2] = st[sp - 2] - st[sp - 1]; sp--; break;
            case 4: st[sp - 2] = st[sp - 2] * st[sp - 1]; sp--; break;
            case 5: if (!st[--sp]) return -1; break;           /* div guard */
            case 6: st[sp - 2] = st[sp - 1] ? st[sp - 2] / st[sp - 1] : 0; sp--; break;
            case 7: pc = code[pc]; break;                      /* jmp */
            case 8: if (!st[--sp]) pc = code[pc]; else pc++; break;
            case 9: return sp ? st[sp - 1] : 0;                /* ret */
            default: return -2;
        }
    }
    return sp ? st[sp - 1] : 0;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)pa_parse_uint,   (variant_fn)pa_parse_int,
    (variant_fn)pa_parse_hex,    (variant_fn)pa_overflow_check,
    (variant_fn)pa_recursive_descent, (variant_fn)pa_shunting_yard,
    (variant_fn)pa_lexer_switch, (variant_fn)pa_lexer_dfa,
    (variant_fn)pa_json_skip,    (variant_fn)pa_csv_field,
    (variant_fn)pa_ini_line,     (variant_fn)pa_bytecode_vm,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}
