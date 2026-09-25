/* 31. C++ Lambdas & Closures family. */
#include <cstdint>
#include <cstddef>
#include <functional>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(la_no_capture);
int la_no_capture(int x) {
    MARK(la_no_capture);
    auto f = [](int v) { return v * 3 + 1; };
    return f(x);
}
TAG(la_by_value);
int la_by_value(int base, int k) {
    MARK(la_by_value);
    int factor = base + k;
    auto f = [factor](int v) { return v * factor; };
    return f(k);
}
TAG(la_by_ref);
int la_by_ref(int n) {
    MARK(la_by_ref);
    int acc = 0;
    auto f = [&acc](int v) { acc += v; };
    for (int i = 1; i <= n; i++) f(i);
    return acc;
}
TAG(la_mutable);
int la_mutable(int n) {
    MARK(la_mutable);
    int counter = 0;
    auto f = [counter]() mutable { return ++counter; };
    int last = 0;
    for (int i = 0; i < n; i++) last = f();
    return last;
}
TAG(la_multi_capture);
int la_multi_capture(int a, int b, int c) {
    MARK(la_multi_capture);
    int m = a * b;
    auto f = [m, &c](int v) { c += m; return v + c; };
    return f(a) + f(b);
}
TAG(la_generic);
int la_generic(int x, double d) {
    MARK(la_generic);
    auto f = [](auto v) { return v + v; };
    return f(x) + (int)f(d);
}
TAG(la_std_function);
int la_std_function(int x) {
    MARK(la_std_function);
    std::function<int(int)> f = [](int v) { return v + 7; };
    std::function<int(int)> g = [&f](int v) { return f(v) * 2; };
    return g(x);
}
TAG(la_std_function_chain);
int la_std_function_chain(int x) {
    MARK(la_std_function_chain);
    std::function<int(int)> h;
    h = [&h](int v) { return v <= 1 ? 1 : v * h(v - 1); };
    return h(x & 7);
}
TAG(la_lambda_in_algo);
int la_lambda_in_algo(const int *arr, int n) {
    MARK(la_lambda_in_algo);
    int threshold = n > 0 ? arr[0] : 0;
    int count = 0;
    auto pred = [threshold](int v) { return v > threshold; };
    for (int i = 0; i < n; i++)
        if (pred(arr[i])) count++;
    return count;
}
TAG(la_nested_lambda);
int la_nested_lambda(int x) {
    MARK(la_nested_lambda);
    auto outer = [](int a) {
        auto inner = [](int b) { return b * b; };
        return inner(a) + a;
    };
    return outer(x);
}
TAG(la_immediately_invoked);
int la_immediately_invoked(int x) {
    MARK(la_immediately_invoked);
    return [x](int v) { return v * x; }(x + 1);
}

typedef int (*variant_fn)(int);
static variant_fn g_variants[] = {
    reinterpret_cast<variant_fn>(la_no_capture),
    reinterpret_cast<variant_fn>(la_by_value),
    reinterpret_cast<variant_fn>(la_by_ref),
    reinterpret_cast<variant_fn>(la_mutable),
    reinterpret_cast<variant_fn>(la_multi_capture),
    reinterpret_cast<variant_fn>(la_generic),
    reinterpret_cast<variant_fn>(la_std_function),
    reinterpret_cast<variant_fn>(la_std_function_chain),
    reinterpret_cast<variant_fn>(la_lambda_in_algo),
    reinterpret_cast<variant_fn>(la_nested_lambda),
    reinterpret_cast<variant_fn>(la_immediately_invoked),
};
int main() {
    volatile int sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
