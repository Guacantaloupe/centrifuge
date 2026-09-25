/* 17. Dynamic Programming family. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(dp_fib_naive);
uint64_t dp_fib_naive(int n) {
    MARK(dp_fib_naive);
    if (n < 2) return (uint64_t)n;
    return dp_fib_naive(n - 1) + dp_fib_naive(n - 2);
}
TAG(dp_fib_memo);
static uint64_t g_fibmemo[64];
static uint64_t fib_memo_run(int n) {
    if (n < 2) return (uint64_t)n;
    if (g_fibmemo[n]) return g_fibmemo[n];
    return g_fibmemo[n] = fib_memo_run(n - 1) + fib_memo_run(n - 2);
}
uint64_t dp_fib_memo(int n) {
    MARK(dp_fib_memo);
    for (int i = 0; i < 64; i++) g_fibmemo[i] = 0;
    return fib_memo_run(n);
}
TAG(dp_fib_iter);
uint64_t dp_fib_iter(int n) {
    MARK(dp_fib_iter);
    uint64_t a = 0, b = 1;
    for (int i = 0; i < n; i++) { uint64_t t = a + b; a = b; b = t; }
    return a;
}
TAG(dp_fib_fast_doubling);
static void fib_fd(int n, uint64_t *fn, uint64_t *fn1) {
    if (n == 0) { *fn = 0; *fn1 = 1; return; }
    uint64_t a, b;
    fib_fd(n >> 1, &a, &b);
    uint64_t c = a * (2 * b - a);
    uint64_t d = a * a + b * b;
    if (n & 1) { *fn = d; *fn1 = c + d; }
    else { *fn = c; *fn1 = d; }
}
uint64_t dp_fib_fast_doubling(int n) {
    MARK(dp_fib_fast_doubling);
    uint64_t fn, fn1;
    fib_fd(n, &fn, &fn1);
    return fn;
}
static int g_knapsack_w[32], g_knapsack_v[32];
TAG(dp_knapsack_recursive);
int dp_knapsack_recursive(int i, int cap) {
    MARK(dp_knapsack_recursive);
    if (i < 0 || cap <= 0) return 0;
    int skip = dp_knapsack_recursive(i - 1, cap);
    if (g_knapsack_w[i] > cap) return skip;
    int take = g_knapsack_v[i] + dp_knapsack_recursive(i - 1, cap - g_knapsack_w[i]);
    return take > skip ? take : skip;
}
TAG(dp_knapsack_2d);
int dp_knapsack_2d(int n, int cap) {
    MARK(dp_knapsack_2d);
    static int dp[32][64];
    for (int i = 0; i <= n; i++)
        for (int c = 0; c <= cap; c++) {
            if (i == 0 || c == 0) { dp[i][c] = 0; continue; }
            dp[i][c] = dp[i - 1][c];
            if (g_knapsack_w[i - 1] <= c) {
                int t = g_knapsack_v[i - 1] + dp[i - 1][c - g_knapsack_w[i - 1]];
                if (t > dp[i][c]) dp[i][c] = t;
            }
        }
    return dp[n][cap];
}
TAG(dp_knapsack_1d);
int dp_knapsack_1d(int n, int cap) {
    MARK(dp_knapsack_1d);
    static int dp[64];
    for (int c = 0; c <= cap; c++) dp[c] = 0;
    for (int i = 0; i < n; i++)
        for (int c = cap; c >= g_knapsack_w[i]; c--) {
            int t = g_knapsack_v[i] + dp[c - g_knapsack_w[i]];
            if (t > dp[c]) dp[c] = t;
        }
    return dp[cap];
}
TAG(dp_knapsack_backwards);
int dp_knapsack_backwards(int n, int cap) {
    MARK(dp_knapsack_backwards);
    return dp_knapsack_1d(n, cap);
}
TAG(dp_lcs_recursive);
int dp_lcs_recursive(const char *a, const char *b, int i, int j) {
    MARK(dp_lcs_recursive);
    if (i < 0 || j < 0) return 0;
    if (a[i] == b[j]) return 1 + dp_lcs_recursive(a, b, i - 1, j - 1);
    int x = dp_lcs_recursive(a, b, i - 1, j);
    int y = dp_lcs_recursive(a, b, i, j - 1);
    return x > y ? x : y;
}
TAG(dp_lcs_matrix);
int dp_lcs_matrix(const char *a, const char *b, int n, int m) {
    MARK(dp_lcs_matrix);
    static int dp[40][40];
    for (int i = 0; i <= n; i++)
        for (int j = 0; j <= m; j++) {
            if (!i || !j) { dp[i][j] = 0; continue; }
            dp[i][j] = a[i - 1] == b[j - 1] ? dp[i - 1][j - 1] + 1
                     : dp[i - 1][j] > dp[i][j - 1] ? dp[i - 1][j] : dp[i][j - 1];
        }
    return dp[n][m];
}
TAG(dp_lcs_rolling);
int dp_lcs_rolling(const char *a, const char *b, int n, int m) {
    MARK(dp_lcs_rolling);
    static int prev[40], cur[40];
    for (int i = 0; i <= n; i++)
        for (int j = 0; j <= m; j++) {
            if (!i || !j) { cur[j] = 0; continue; }
            int v = a[i - 1] == b[j - 1] ? prev[j - 1] + 1
                    : prev[j] > cur[j - 1] ? prev[j] : cur[j - 1];
            prev[j - 1] = cur[j - 1];
            cur[j] = v;
            if (j == m) prev[j] = v;
        }
    return prev[m];
}
TAG(dp_edit_distance);
int dp_edit_distance(const char *a, int n, const char *b, int m) {
    MARK(dp_edit_distance);
    static int dp[40][40];
    for (int i = 0; i <= n; i++) dp[i][0] = i;
    for (int j = 0; j <= m; j++) dp[0][j] = j;
    for (int i = 1; i <= n; i++)
        for (int j = 1; j <= m; j++) {
            int sub = dp[i - 1][j - 1] + (a[i - 1] != b[j - 1]);
            int del = dp[i - 1][j] + 1;
            int ins = dp[i][j - 1] + 1;
            int best = sub < del ? sub : del;
            dp[i][j] = best < ins ? best : ins;
        }
    return dp[n][m];
}
TAG(dp_lis_n2);
int dp_lis_n2(const int *a, int n) {
    MARK(dp_lis_n2);
    static int len[64];
    int best = 0;
    for (int i = 0; i < n; i++) {
        len[i] = 1;
        for (int j = 0; j < i; j++)
            if (a[j] < a[i] && len[j] + 1 > len[i]) len[i] = len[j] + 1;
        if (len[i] > best) best = len[i];
    }
    return best;
}
TAG(dp_lis_nlogn);
int dp_lis_nlogn(const int *a, int n) {
    MARK(dp_lis_nlogn);
    static int tail[64];
    int len = 0;
    for (int i = 0; i < n; i++) {
        int lo = 0, hi = len;
        while (lo < hi) {
            int m = (lo + hi) / 2;
            if (tail[m] < a[i]) lo = m + 1; else hi = m;
        }
        tail[lo] = a[i];
        if (lo == len) len++;
    }
    return len;
}
TAG(dp_coin_change);
int dp_coin_change(const int *coins, int nc, int amount) {
    MARK(dp_coin_change);
    static int dp[256];
    for (int i = 1; i <= amount; i++) dp[i] = 0x3fffffff;
    dp[0] = 0;
    for (int i = 1; i <= amount; i++)
        for (int c = 0; c < nc; c++)
            if (coins[c] <= i && dp[i - coins[c]] + 1 < dp[i])
                dp[i] = dp[i - coins[c]] + 1;
    return dp[amount];
}
TAG(dp_subset_sum);
int dp_subset_sum(const int *a, int n, int target) {
    MARK(dp_subset_sum);
    static uint8_t dp[256];
    dp[0] = 1;
    for (int i = 0; i < n; i++)
        for (int s = target; s >= a[i]; s--)
            dp[s] |= dp[s - a[i]];
    return dp[target];
}
TAG(dp_matrix_chain);
int dp_matrix_chain(const int *dims, int n) {
    MARK(dp_matrix_chain);
    static int dp[32][32];
    for (int len = 2; len <= n; len++)
        for (int i = 0; i + len <= n; i++) {
            int j = i + len;
            dp[i][j] = 0x3fffffff;
            for (int k = i + 1; k < j; k++) {
                int c = dp[i][k] + dp[k][j] + dims[i] * dims[k] * dims[j];
                if (c < dp[i][j]) dp[i][j] = c;
            }
        }
    return dp[0][n];
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)dp_fib_naive,     (variant_fn)dp_fib_memo,
    (variant_fn)dp_fib_iter,      (variant_fn)dp_fib_fast_doubling,
    (variant_fn)dp_knapsack_recursive, (variant_fn)dp_knapsack_2d,
    (variant_fn)dp_knapsack_1d,   (variant_fn)dp_knapsack_backwards,
    (variant_fn)dp_lcs_recursive, (variant_fn)dp_lcs_matrix,
    (variant_fn)dp_lcs_rolling,   (variant_fn)dp_edit_distance,
    (variant_fn)dp_lis_n2,        (variant_fn)dp_lis_nlogn,
    (variant_fn)dp_coin_change,   (variant_fn)dp_subset_sum,
    (variant_fn)dp_matrix_chain,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}
