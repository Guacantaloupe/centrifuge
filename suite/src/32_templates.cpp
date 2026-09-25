/* 32. C++ Templates & Metaprogramming family. */
#include <cstdint>
#include <cstddef>
#include <cstdarg>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(tm_max_int);
int tm_max_int(int a, int b) {
    MARK(tm_max_int);
    return a > b ? a : b;
}
TAG(tm_max_double);
double tm_max_double(double a, double b) {
    MARK(tm_max_double);
    return a > b ? a : b;
}
TAG(tm_abs_int);
int tm_abs_int(int x) {
    MARK(tm_abs_int);
    return x < 0 ? -x : x;
}
TAG(tm_clamp_long);
long tm_clamp_long(long v, long lo, long hi) {
    MARK(tm_clamp_long);
    return v < lo ? lo : v > hi ? hi : v;
}
TAG(tm_swap_ints);
void tm_swap_ints(int *a, int *b) {
    MARK(tm_swap_ints);
    int t = *a; *a = *b; *b = t;
}
TAG(tm_spec_factorial);
unsigned tm_spec_factorial(unsigned n) {
    MARK(tm_spec_factorial);
    /* full specialization style: iterative wrapper around generic shape */
    return n <= 1 ? 1 : n * tm_spec_factorial(n - 1);
}
TAG(tm_pair_sum);
int tm_pair_sum(int a, int b) {
    MARK(tm_pair_sum);
    return a + b;
}
TAG(tm_pair_scale);
int tm_pair_scale(int a, int k) {
    MARK(tm_pair_scale);
    return a * k + k;
}
TAG(tm_sizeof_probe);
size_t tm_sizeof_probe(int which) {
    MARK(tm_sizeof_probe);
    switch (which) {
    case 0: return sizeof(char);
    case 1: return sizeof(short);
    case 2: return sizeof(int);
    case 3: return sizeof(long long);
    case 4: return sizeof(void *);
    default: return sizeof(double);
    }
}
TAG(tm_accumulate_int);
int tm_accumulate_int(const int *arr, int n) {
    MARK(tm_accumulate_int);
    int s = 0;
    for (int i = 0; i < n; i++) s += arr[i];
    return s;
}
TAG(tm_accumulate_long);
long tm_accumulate_long(const long *arr, int n) {
    MARK(tm_accumulate_long);
    long s = 0;
    for (int i = 0; i < n; i++) s += arr[i];
    return s;
}
TAG(tm_accumulate_double);
double tm_accumulate_double(const double *arr, int n) {
    MARK(tm_accumulate_double);
    double s = 0.0;
    for (int i = 0; i < n; i++) s += arr[i];
    return s;
}
TAG(tm_variadic_sum);
int tm_variadic_sum(int n, ...) {
    MARK(tm_variadic_sum);
    /* hand-rolled variadic sum via va_arg */
    va_list ap;
    va_start(ap, n);
    int s = 0;
    for (int i = 0; i < n; i++) s += va_arg(ap, int);
    va_end(ap);
    return s;
}
TAG(tm_crtp_counter);
int tm_crtp_counter(int steps) {
    MARK(tm_crtp_counter);
    /* CRTP shape: derived increments its own static counter */
    struct counter_impl {
        static int &value() { static int v = 0; return v; }
        static void step(int n) { value() += n; }
    };
    for (int i = 0; i < steps; i++) counter_impl::step(2);
    return counter_impl::value();
}
TAG(tm_meta_pow2);
unsigned tm_meta_pow2(unsigned e) {
    MARK(tm_meta_pow2);
    /* compile-time style unrolled powers of two */
    switch (e & 7u) {
    case 0: return 1u;
    case 1: return 2u;
    case 2: return 4u;
    case 3: return 8u;
    case 4: return 16u;
    case 5: return 32u;
    case 6: return 64u;
    default: return 128u;
    }
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    reinterpret_cast<variant_fn>(tm_max_int),
    reinterpret_cast<variant_fn>(tm_max_double),
    reinterpret_cast<variant_fn>(tm_abs_int),
    reinterpret_cast<variant_fn>(tm_clamp_long),
    reinterpret_cast<variant_fn>(tm_swap_ints),
    reinterpret_cast<variant_fn>(tm_spec_factorial),
    reinterpret_cast<variant_fn>(tm_pair_sum),
    reinterpret_cast<variant_fn>(tm_pair_scale),
    reinterpret_cast<variant_fn>(tm_sizeof_probe),
    reinterpret_cast<variant_fn>(tm_accumulate_int),
    reinterpret_cast<variant_fn>(tm_accumulate_long),
    reinterpret_cast<variant_fn>(tm_accumulate_double),
    reinterpret_cast<variant_fn>(tm_variadic_sum),
    reinterpret_cast<variant_fn>(tm_crtp_counter),
    reinterpret_cast<variant_fn>(tm_meta_pow2),
};
int main() {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
