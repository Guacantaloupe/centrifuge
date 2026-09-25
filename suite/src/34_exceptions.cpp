/* 34. C++ Exceptions & RAII family. */
#include <cstdint>
#include <cstddef>
#include <exception>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(ex_simple_try);
int ex_simple_try(int x) {
    MARK(ex_simple_try);
    try {
        if (x < 0) throw -1;
        return x * 2;
    } catch (int e) {
        return e - 100;
    }
}
TAG(ex_throw_value);
int ex_throw_value(int x) {
    MARK(ex_throw_value);
    struct tiny { int code; };
    try {
        if (x == 0) throw tiny{42};
        return x;
    } catch (const tiny &t) {
        return t.code;
    }
}
TAG(ex_rethrow);
int ex_rethrow(int x) {
    MARK(ex_rethrow);
    try {
        try {
            if (x > 10) throw 1;
            if (x < 0) throw 2;
            return 0;
        } catch (int inner) {
            if (inner == 2) throw; /* rethrow */
            return inner + 10;
        }
    } catch (int outer) {
        return outer + 100;
    }
}
TAG(ex_multi_catch);
int ex_multi_catch(int x) {
    MARK(ex_multi_catch);
    try {
        if (x == 1) throw 1;
        if (x == 2) throw 2.5;
        if (x == 3) throw 'c';
        return 0;
    } catch (int) {
        return 1;
    } catch (double) {
        return 2;
    } catch (...) {
        return 3;
    }
}
TAG(ex_catch_all);
int ex_catch_all(int x) {
    MARK(ex_catch_all);
    try {
        if (x) throw x;
        return 7;
    } catch (...) {
        return -7;
    }
}
TAG(ex_raii_guard);
int ex_raii_guard(int n) {
    MARK(ex_raii_guard);
    struct guard {
        int &ref;
        explicit guard(int &r) : ref(r) { ref++; }
        ~guard() { ref--; }
    };
    int counter = 0;
    for (int i = 0; i < n; i++) {
        guard g(counter);
        counter += 2;
    }
    return counter;
}
TAG(ex_raii_filelike);
int ex_raii_filelike(int n) {
    MARK(ex_raii_filelike);
    struct resource {
        int *buf;
        explicit resource(int sz) : buf(new int[sz]) {}
        ~resource() { delete[] buf; }
        int &at(int i) { return buf[i]; }
    };
    resource r(8);
    for (int i = 0; i < 8; i++) r.at(i) = i * n;
    return r.at(3);
}
TAG(ex_noexcept_func);
int ex_noexcept_func(int x) noexcept {
    MARK(ex_noexcept_func);
    return x >= 0 ? x : -x;
}
TAG(ex_unwind_loop);
int ex_unwind_loop(int n) {
    MARK(ex_unwind_loop);
    int acc = 0;
    for (int i = 0; i < n; i++) {
        try {
            if ((i % 5) == 4) throw i;
            acc += i;
        } catch (int e) {
            acc -= e / 2;
        }
    }
    return acc;
}
TAG(ex_nested_deep);
int ex_nested_deep(int x) {
    MARK(ex_nested_deep);
    int state = 0;
    try {
        try {
            try {
                if (x > 100) throw 1;
                state += 1;
                if (x > 50) throw 2;
                state += 10;
            } catch (int e) {
                state += e * 100;
                if (e == 2) throw;
            }
            state += 1000;
        } catch (short) {
            state = -1;
        } catch (int e) {
            state += e * 10000;
        }
    } catch (...) {
        state = -2;
    }
    return state;
}
TAG(ex_std_exception);
int ex_std_exception(int x) {
    MARK(ex_std_exception);
    try {
        if (x < 0) throw std::exception();
        return x;
    } catch (const std::exception &) {
        return -1;
    }
}

typedef int (*variant_fn)(int);
static variant_fn g_variants[] = {
    ex_simple_try,    ex_throw_value, ex_rethrow,      ex_multi_catch,
    ex_catch_all,     ex_raii_guard,  ex_raii_filelike, ex_noexcept_func,
    ex_unwind_loop,   ex_nested_deep, ex_std_exception,
};
int main() {
    volatile int sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
