/* 39. Loop Recovery family — for/while/do-while/break/continue reconstruction. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(lp_count_up);
int lp_count_up(int n) {
    MARK(lp_count_up);
    int s = 0;
    for (int i = 0; i < n; i++) s += i;
    return s;
}
TAG(lp_count_down);
int lp_count_down(int n) {
    MARK(lp_count_down);
    int s = 0;
    for (int i = n; i > 0; i--) s += i * i;
    return s;
}
TAG(lp_while_loop);
int lp_while_loop(int n) {
    MARK(lp_while_loop);
    int i = 1, p = 1;
    while (p < n) {
        p *= 2;
        i++;
    }
    return i;
}
TAG(lp_do_while);
int lp_do_while(int n) {
    MARK(lp_do_while);
    int x = n;
    int steps = 0;
    do {
        x = x & 1 ? 3 * x + 1 : x / 2;
        steps++;
    } while (x != 1 && steps < 1000);
    return steps;
}
TAG(lp_break_early);
int lp_break_early(const int *arr, int n, int key) {
    MARK(lp_break_early);
    int found = -1;
    for (int i = 0; i < n; i++) {
        if (arr[i] == key) {
            found = i;
            break;
        }
    }
    return found;
}
TAG(lp_continue_skip);
int lp_continue_skip(const int *arr, int n) {
    MARK(lp_continue_skip);
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (arr[i] < 0) continue;
        if (arr[i] == 0) break;
        s += arr[i];
    }
    return s;
}
TAG(lp_nested_for);
int lp_nested_for(int n) {
    MARK(lp_nested_for);
    int s = 0;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            s += (i ^ j) & 1;
    return s;
}
TAG(lp_triple_nested);
int lp_triple_nested(int n) {
    MARK(lp_triple_nested);
    int s = 0;
    for (int i = 0; i < n; i++)
        for (int j = i; j < n; j++)
            for (int k = j; k < n; k++)
                if ((i + j + k) % 7 == 0) s++;
    return s;
}
TAG(lp_infinite_guard);
int lp_infinite_guard(volatile int *stop, int seed) {
    MARK(lp_infinite_guard);
    int x = seed, iters = 0;
    for (;;) {
        x = x * 1103515245 + 12345;
        iters++;
        if (*stop || iters > 1000) break;
    }
    return x;
}
TAG(lp_two_exits);
int lp_two_exits(const int *arr, int n) {
    MARK(lp_two_exits);
    /* loop with break and normal exit merging */
    int s = 0, i = 0;
    for (; i < n; i++) {
        if (arr[i] < 0) break;
        s += arr[i];
    }
    if (i < n) s = -s;
    return s;
}
TAG(lp_loop_carried_dep);
int lp_loop_carried_dep(int n) {
    MARK(lp_loop_carried_dep);
    /* fibonacci: tight loop-carried dependency, hard to vectorize */
    int a = 0, b = 1;
    for (int i = 0; i < n; i++) {
        int t = a + b;
        a = b;
        b = t;
    }
    return a;
}
TAG(lp_strided);
long long lp_strided(const short *arr, int n, int step) {
    MARK(lp_strided);
    long long s = 0;
    for (int i = 0; i < n; i += step) s += arr[i];
    return s;
}
TAG(lp_reverse_iter);
int lp_reverse_iter(const int *arr, int n) {
    MARK(lp_reverse_iter);
    int s = 0;
    for (int i = n - 1; i >= 0; i--) s = s * 31 + arr[i];
    return s;
}
TAG(lp_bit_loop);
int lp_bit_loop(uint32_t x) {
    MARK(lp_bit_loop);
    int count = 0;
    while (x) {
        x &= x - 1;
        count++;
    }
    return count;
}
TAG(lp_outer_break);
int lp_outer_break(int n) {
    MARK(lp_outer_break);
    int found = 0;
    for (int i = 0; i < n && !found; i++)
        for (int j = 0; j < n && !found; j++)
            if ((i * j) % 13 == 7) found = i * n + j;
    return found;
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)lp_count_up,        (variant_fn)lp_count_down,
    (variant_fn)lp_while_loop,      (variant_fn)lp_do_while,
    (variant_fn)lp_break_early,     (variant_fn)lp_continue_skip,
    (variant_fn)lp_nested_for,      (variant_fn)lp_triple_nested,
    (variant_fn)lp_infinite_guard,  (variant_fn)lp_two_exits,
    (variant_fn)lp_loop_carried_dep, (variant_fn)lp_strided,
    (variant_fn)lp_reverse_iter,    (variant_fn)lp_bit_loop,
    (variant_fn)lp_outer_break,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
