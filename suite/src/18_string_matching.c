/* 18. String Matching family. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(sm_naive);
int sm_naive(const char *text, const char *pat) {
    MARK(sm_naive);
    int n = 0, m = 0;
    while (text[n]) n++;
    while (pat[m]) m++;
    for (int i = 0; i + m <= n; i++) {
        int j = 0;
        while (j < m && text[i + j] == pat[j]) j++;
        if (j == m) return i;
    }
    return -1;
}
TAG(sm_kmp);
int sm_kmp(const char *text, int n, const char *pat, int m) {
    MARK(sm_kmp);
    static int lps[64];
    lps[0] = 0;
    for (int i = 1, len = 0; i < m;) {
        if (pat[i] == pat[len]) lps[i++] = ++len;
        else if (len) len = lps[len - 1];
        else lps[i++] = 0;
    }
    for (int i = 0, j = 0; i < n;) {
        if (text[i] == pat[j]) { i++; j++; }
        if (j == m) return i - j;
        else if (i < n && text[i] != pat[j]) j ? (j = lps[j - 1]) : i++;
    }
    return -1;
}
TAG(sm_boyer_moore);
int sm_boyer_moore(const unsigned char *text, int n,
                   const unsigned char *pat, int m) {
    MARK(sm_boyer_moore);
    int bad[256];
    for (int i = 0; i < 256; i++) bad[i] = m;
    for (int i = 0; i < m - 1; i++) bad[pat[i]] = m - 1 - i;
    int s = 0;
    while (s <= n - m) {
        int j = m - 1;
        while (j >= 0 && pat[j] == text[s + j]) j--;
        if (j < 0) return s;
        s += bad[text[s + m - 1]] > m - 1 - j ? bad[text[s + m - 1]] : 1;
    }
    return -1;
}
TAG(sm_horspool);
int sm_horspool(const unsigned char *text, int n,
                const unsigned char *pat, int m) {
    MARK(sm_horspool);
    int skip[256];
    for (int i = 0; i < 256; i++) skip[i] = m;
    for (int i = 0; i < m - 1; i++) skip[pat[i]] = m - 1 - i;
    int s = 0;
    while (s <= n - m) {
        int j = m - 1;
        while (j >= 0 && pat[j] == text[s + j]) j--;
        if (j < 0) return s;
        s += skip[text[s + m - 1]];
    }
    return -1;
}
TAG(sm_rabin_karp);
int sm_rabin_karp(const unsigned char *text, int n,
                  const unsigned char *pat, int m) {
    MARK(sm_rabin_karp);
    const unsigned p = 16777619u;
    unsigned h = 1, th = 0, ph = 0;
    for (int i = 0; i < m - 1; i++) h = h * 256u % p;
    for (int i = 0; i < m; i++) {
        ph = (ph * 256u + pat[i]) % p;
        th = (th * 256u + text[i]) % p;
    }
    for (int s = 0; s <= n - m; s++) {
        if (ph == th) {
            int j = 0;
            while (j < m && text[s + j] == pat[j]) j++;
            if (j == m) return s;
        }
        if (s < n - m)
            th = (unsigned)((th + p - (unsigned)text[s] * h % p) % p) * 256u % p,
            th = (th + text[s + m]) % p;
    }
    return -1;
}
TAG(sm_z_algo);
int sm_z_algo(const unsigned char *s, int n) {
    MARK(sm_z_algo);
    static int z[128];
    int l = 0, r = 0;
    for (int i = 1; i < n; i++) {
        if (i < r) z[i] = z[i - l] < r - i ? z[i - l] : r - i;
        while (i + z[i] < n && s[z[i]] == s[i + z[i]]) z[i]++;
        if (i + z[i] > r) { l = i; r = i + z[i]; }
    }
    return z[1];
}
struct acnode { int next[4]; int fail; int out; };
static struct acnode g_ac[64];
TAG(sm_aho_corasick_step);
int sm_aho_corasick_step(int state, unsigned char c) {
    MARK(sm_aho_corasick_step);
    int sym = c & 3;
    while (state && !g_ac[state].next[sym]) state = g_ac[state].fail;
    state = g_ac[state].next[sym] ? g_ac[state].next[sym] : 0;
    return g_ac[state].out ? state : -state;
}
TAG(sm_case_insensitive);
int sm_case_insensitive(const char *text, const char *pat) {
    MARK(sm_case_insensitive);
    int n = 0, m = 0;
    while (text[n]) n++;
    while (pat[m]) m++;
    for (int i = 0; i + m <= n; i++) {
        int j = 0;
        while (j < m) {
            char a = text[i + j], b = pat[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
            j++;
        }
        if (j == m) return i;
    }
    return -1;
}
TAG(sm_pointer_strings);
int sm_pointer_strings(const char *t, const char *p,
                       char (*norm)(char)) {
    MARK(sm_pointer_strings);
    for (const char *s = t; *s; s++) {
        const char *a = s, *b = p;
        while (*b && *a && *a == (norm ? norm(*b) : *b)) { a++; b++; }
        if (!*b) return (int)(s - t);
    }
    return -1;
}
TAG(sm_utf8_byte_oriented);
int sm_utf8_byte_oriented(const unsigned char *t, int n,
                          uint32_t cp) {
    MARK(sm_utf8_byte_oriented);
    unsigned char seq[4];
    int m = 0;
    if (cp < 0x80) seq[m++] = (unsigned char)cp;
    else if (cp < 0x800) { seq[m++] = 0xC0 | (cp >> 6); seq[m++] = 0x80 | (cp & 63); }
    else if (cp < 0x10000) {
        seq[m++] = 0xE0 | (cp >> 12);
        seq[m++] = 0x80 | ((cp >> 6) & 63);
        seq[m++] = 0x80 | (cp & 63);
    } else {
        seq[m++] = 0xF0 | (cp >> 18);
        seq[m++] = 0x80 | ((cp >> 12) & 63);
        seq[m++] = 0x80 | ((cp >> 6) & 63);
        seq[m++] = 0x80 | (cp & 63);
    }
    for (int i = 0; i + m <= n; i++) {
        int j = 0;
        while (j < m && t[i + j] == seq[j]) j++;
        if (j == m) return i;
    }
    return -1;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)sm_naive,            (variant_fn)sm_kmp,
    (variant_fn)sm_boyer_moore,      (variant_fn)sm_horspool,
    (variant_fn)sm_rabin_karp,       (variant_fn)sm_z_algo,
    (variant_fn)sm_aho_corasick_step,(variant_fn)sm_case_insensitive,
    (variant_fn)sm_pointer_strings,  (variant_fn)sm_utf8_byte_oriented,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}
