/* 35. Function ABI & Calling Conventions family. */
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(abi_zero_args);
int abi_zero_args(void) {
    MARK(abi_zero_args);
    return 42;
}
TAG(abi_one_arg);
int abi_one_arg(int a) {
    MARK(abi_one_arg);
    return a + 1;
}
TAG(abi_four_args);
int abi_four_args(int a, int b, int c, int d) {
    MARK(abi_four_args);
    return a + b * 2 + c * 3 + d * 4;
}
TAG(abi_eight_args);
int abi_eight_args(int a, int b, int c, int d, int e, int f, int g, int h) {
    MARK(abi_eight_args);
    return a + b + c + d + e + f + g + h;
}
TAG(abi_sixteen_args);
long long abi_sixteen_args(int a1, int a2, int a3, int a4, int a5, int a6,
                           int a7, int a8, int a9, int a10, int a11, int a12,
                           int a13, int a14, int a15, int a16) {
    MARK(abi_sixteen_args);
    return (long long)a1 + a2 * 2 + a3 * 3 + a4 * 4 + a5 * 5 + a6 * 6 +
           a7 * 7 + a8 * 8 + a9 * 9 + a10 * 10 + a11 * 11 + a12 * 12 +
           a13 * 13 + a14 * 14 + a15 * 15 + a16 * 16;
}
TAG(abi_mixed_int_widths);
long long abi_mixed_int_widths(char c, short s, int i, long l, long long ll,
                               unsigned char uc, unsigned short us,
                               unsigned int ui, unsigned long ul) {
    MARK(abi_mixed_int_widths);
    return (long long)c + s + i + l + ll + uc + us + ui + ul;
}
TAG(abi_float_args);
double abi_float_args(float a, double b, float c, double d) {
    MARK(abi_float_args);
    return a * b + c * d;
}
TAG(abi_mixed_float_int);
double abi_mixed_float_int(int a, double b, int c, float d, long long e) {
    MARK(abi_mixed_float_int);
    return a * b + c * d + (double)e;
}
TAG(abi_ptr_args);
int abi_ptr_args(const int *a, int *b, void *c, const void *d) {
    MARK(abi_ptr_args);
    *b = *a + (int)(size_t)c;
    return *b + (d != 0);
}
struct small_pod { int x, y; };
struct big_pod { long long v[6]; };
struct odd_pod { char c; double d; };
TAG(abi_ret_small_struct);
struct small_pod abi_ret_small_struct(int x) {
    MARK(abi_ret_small_struct);
    struct small_pod r = {x, x * 2};
    return r;
}
TAG(abi_arg_small_struct);
int abi_arg_small_struct(struct small_pod p, int k) {
    MARK(abi_arg_small_struct);
    return p.x * k + p.y;
}
TAG(abi_arg_big_struct);
long long abi_arg_big_struct(struct big_pod p, int k) {
    MARK(abi_arg_big_struct);
    long long s = k;
    for (int i = 0; i < 6; i++) s += p.v[i];
    return s;
}
TAG(abi_arg_odd_struct);
double abi_arg_odd_struct(struct odd_pod p, int k) {
    MARK(abi_arg_odd_struct);
    return p.d * k + p.c;
}
TAG(abi_ret_big_struct);
struct big_pod abi_ret_big_struct(int k) {
    MARK(abi_ret_big_struct);
    struct big_pod r;
    for (int i = 0; i < 6; i++) r.v[i] = k * (i + 1);
    return r;
}
TAG(abi_variadic_count);
int abi_variadic_count(int n, ...) {
    MARK(abi_variadic_count);
    va_list ap;
    va_start(ap, n);
    int s = 0;
    for (int i = 0; i < n; i++) s += va_arg(ap, int);
    va_end(ap);
    return s;
}
TAG(abi_variadic_mixed);
double abi_variadic_mixed(int n, ...) {
    MARK(abi_variadic_mixed);
    va_list ap;
    va_start(ap, n);
    double s = 0.0;
    for (int i = 0; i < n; i++) {
        if (i & 1) s += va_arg(ap, double);
        else s += va_arg(ap, int);
    }
    va_end(ap);
    return s;
}
TAG(abi_fn_pointer_cb);
int abi_fn_pointer_cb(int (*cb)(int, int), int x, int y) {
    MARK(abi_fn_pointer_cb);
    return cb(x, y) * 2;
}
TAG(abi_static_helper);
static int abi_cb_impl(int a, int b) { return a * b; }
TAG(abi_use_callback);
int abi_use_callback(int x) {
    MARK(abi_use_callback);
    return abi_fn_pointer_cb(abi_cb_impl, x, x + 1);
}
TAG(abi_struct_byval_ptr_out);
void abi_struct_byval_ptr_out(struct small_pod p, int *out) {
    MARK(abi_struct_byval_ptr_out);
    *out = p.x + p.y;
}
TAG(abi_many_ptrs);
long long abi_many_ptrs(long long *a, long long *b, long long *c, long long *d,
                        long long *e, long long *f) {
    MARK(abi_many_ptrs);
    *a += 1; *b += 2; *c += 3; *d += 4; *e += 5; *f += 6;
    return *a + *b + *c + *d + *e + *f;
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)abi_zero_args,        (variant_fn)abi_one_arg,
    (variant_fn)abi_four_args,        (variant_fn)abi_eight_args,
    (variant_fn)abi_sixteen_args,     (variant_fn)abi_mixed_int_widths,
    (variant_fn)abi_float_args,       (variant_fn)abi_mixed_float_int,
    (variant_fn)abi_ptr_args,         (variant_fn)abi_ret_small_struct,
    (variant_fn)abi_arg_small_struct, (variant_fn)abi_arg_big_struct,
    (variant_fn)abi_arg_odd_struct,   (variant_fn)abi_ret_big_struct,
    (variant_fn)abi_variadic_count,   (variant_fn)abi_variadic_mixed,
    (variant_fn)abi_fn_pointer_cb,    (variant_fn)abi_use_callback,
    (variant_fn)abi_struct_byval_ptr_out, (variant_fn)abi_many_ptrs,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
