/* 41. Recursion family — direct, tail, mutual, tree, memoized. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(rc_factorial);
long long rc_factorial(int n) {
    MARK(rc_factorial);
    return n <= 1 ? 1 : n * rc_factorial(n - 1);
}
TAG(rc_fibonacci);
long long rc_fibonacci(int n) {
    MARK(rc_fibonacci);
    return n < 2 ? n : rc_fibonacci(n - 1) + rc_fibonacci(n - 2);
}
TAG(rc_tail_sum);
int rc_tail_sum(int n, int acc) {
    MARK(rc_tail_sum);
    return n == 0 ? acc : rc_tail_sum(n - 1, acc + n);
}
TAG(rc_ackermann_small);
int rc_ackermann_small(int m, int n) {
    MARK(rc_ackermann_small);
    if (m == 0) return n + 1;
    if (n == 0) return rc_ackermann_small(m - 1, 1);
    return rc_ackermann_small(m - 1, rc_ackermann_small(m, n - 1));
}
TAG(rc_gcd);
unsigned rc_gcd(unsigned a, unsigned b) {
    MARK(rc_gcd);
    return b == 0 ? a : rc_gcd(b, a % b);
}
TAG(rc_hanoi_moves);
long long rc_hanoi_moves(int n) {
    MARK(rc_hanoi_moves);
    return n <= 0 ? 0 : 2 * rc_hanoi_moves(n - 1) + 1;
}
TAG(rc_tree_height);
struct rc_tree { int val; struct rc_tree *left, *right; };
int rc_tree_height(const struct rc_tree *t) {
    MARK(rc_tree_height);
    if (!t) return 0;
    int l = rc_tree_height(t->left);
    int r = rc_tree_height(t->right);
    return 1 + (l > r ? l : r);
}
TAG(rc_tree_sum);
long long rc_tree_sum(const struct rc_tree *t) {
    MARK(rc_tree_sum);
    return t ? t->val + rc_tree_sum(t->left) + rc_tree_sum(t->right) : 0;
}
TAG(rc_memo_fib);
static long long rc_memo_buf[64];
long long rc_memo_fib(int n) {
    MARK(rc_memo_fib);
    if (n < 2) return n;
    if (rc_memo_buf[n]) return rc_memo_buf[n];
    return rc_memo_buf[n] = rc_memo_fib(n - 1) + rc_memo_fib(n - 2);
}
TAG(rc_mutual_a);
int rc_mutual_b(int n);
int rc_mutual_a(int n) {
    MARK(rc_mutual_a);
    return n <= 0 ? 0 : n + rc_mutual_b(n - 1);
}
TAG(rc_mutual_b);
int rc_mutual_b(int n) {
    MARK(rc_mutual_b);
    return n <= 0 ? 1 : n * rc_mutual_a(n - 1);
}
TAG(rc_binary_search);
int rc_binary_search(const int *arr, int lo, int hi, int key) {
    MARK(rc_binary_search);
    if (lo > hi) return -1;
    int mid = (lo + hi) / 2;
    if (arr[mid] == key) return mid;
    if (arr[mid] < key) return rc_binary_search(arr, mid + 1, hi, key);
    return rc_binary_search(arr, lo, mid - 1, key);
}
TAG(rc_depth_ternary);
long long rc_depth_ternary(int n) {
    MARK(rc_depth_ternary);
    if (n < 1) return 1;
    return rc_depth_ternary(n / 3) + rc_depth_ternary(n / 5) + 1;
}
TAG(rc_indirect_self);
int rc_indirect_self(int n) {
    MARK(rc_indirect_self);
    static int (*self)(int) = rc_indirect_self;
    return n <= 0 ? 0 : n + self(n - 1);
}
TAG(rc_power_fast);
double rc_power_fast(double base, int exp) {
    MARK(rc_power_fast);
    if (exp == 0) return 1.0;
    if (exp < 0) return 1.0 / rc_power_fast(base, -exp);
    double half = rc_power_fast(base, exp / 2);
    return (exp & 1) ? half * half * base : half * half;
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)rc_factorial,    (variant_fn)rc_fibonacci,
    (variant_fn)rc_tail_sum,     (variant_fn)rc_ackermann_small,
    (variant_fn)rc_gcd,          (variant_fn)rc_hanoi_moves,
    (variant_fn)rc_tree_height,  (variant_fn)rc_tree_sum,
    (variant_fn)rc_memo_fib,     (variant_fn)rc_mutual_a,
    (variant_fn)rc_mutual_b,     (variant_fn)rc_binary_search,
    (variant_fn)rc_depth_ternary, (variant_fn)rc_indirect_self,
    (variant_fn)rc_power_fast,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
