/* 43. C++ Atomics & Concurrency Primitives family. */
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <memory>
#include <mutex>

// bare-metal libstdc++ (riscv64-unknown-elf etc.) ships <mutex> but no
// gthread backend, so std::mutex does not exist there
#if defined(__GLIBCXX__) && !defined(_GLIBCXX_HAS_GTHREADS)
#define CF_NO_THREADS 1
#endif

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(at_atomic_counter_inc);
int at_atomic_counter_inc(std::atomic<int> *c, int n) {
    MARK(at_atomic_counter_inc);
    for (int i = 0; i < n; i++) c->fetch_add(1);
    return c->load();
}
TAG(at_atomic_fetch_sub);
int at_atomic_fetch_sub(std::atomic<int> *c, int n) {
    MARK(at_atomic_fetch_sub);
    return c->fetch_sub(n) - n;
}
TAG(at_cas_loop);
int at_cas_loop(std::atomic<int> *c, int expected, int desired) {
    MARK(at_cas_loop);
    int cur = c->load();
    while (!c->compare_exchange_weak(cur, desired))
        ;
    return cur;
}
TAG(at_cas_max);
int at_cas_max(std::atomic<int> *m, int v) {
    MARK(at_cas_max);
    int cur = m->load();
    while (v > cur && !m->compare_exchange_weak(cur, v))
        ;
    return m->load();
}
TAG(at_exchange);
int at_exchange(std::atomic<int> *c, int v) {
    MARK(at_exchange);
    return c->exchange(v);
}
TAG(at_flag_spin);
int at_flag_spin(std::atomic_flag *flag, int spins) {
    MARK(at_flag_spin);
    int i = 0;
    while (flag->test_and_set() && i < spins) i++;
    flag->clear();
    return i;
}
TAG(at_relaxed_sum);
long long at_relaxed_sum(std::atomic<long long> *a, int n) {
    MARK(at_relaxed_sum);
    long long s = 0;
    for (int i = 0; i < n; i++) {
        a->store((long long)i * 2, std::memory_order_relaxed);
        s += a->load(std::memory_order_relaxed);
    }
    return s;
}
TAG(at_seq_cst_ping_pong);
int at_seq_cst_ping_pong(std::atomic<int> *a, std::atomic<int> *b, int n) {
    MARK(at_seq_cst_ping_pong);
    for (int i = 0; i < n; i++) {
        a->store(i + 1);
        b->store(a->load() * 2);
    }
    return b->load();
}
TAG(at_shared_ptr_use);
int at_shared_ptr_use(int n) {
    MARK(at_shared_ptr_use);
    std::shared_ptr<int> p = std::make_shared<int>(7);
    std::weak_ptr<int> w = p;
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (auto q = w.lock()) s += *q + i;
    }
    return s;
}
TAG(at_mutex_guard_style);
int at_mutex_guard_style(int n) {
    MARK(at_mutex_guard_style);
#ifdef CF_NO_THREADS
    static int shared = 0;
    int local = 0;
    for (int i = 0; i < n; i++) {
        shared += i;
        local = shared;
    }
    return local;
#else
    static std::mutex m;
    static int shared = 0;
    int local = 0;
    for (int i = 0; i < n; i++) {
        m.lock();
        shared += i;
        local = shared;
        m.unlock();
    }
    return local;
#endif
}
TAG(at_atomic_ptr);
int at_atomic_ptr(std::atomic<int *> *p, int n) {
    MARK(at_atomic_ptr);
    static int storage[4] = {1, 2, 3, 4};
    int s = 0;
    for (int i = 0; i < n; i++) {
        p->store(&storage[i & 3]);
        int *q = p->load();
        if (q) s += *q;
    }
    return s;
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    reinterpret_cast<variant_fn>(at_atomic_counter_inc),
    reinterpret_cast<variant_fn>(at_atomic_fetch_sub),
    reinterpret_cast<variant_fn>(at_cas_loop),
    reinterpret_cast<variant_fn>(at_cas_max),
    reinterpret_cast<variant_fn>(at_exchange),
    reinterpret_cast<variant_fn>(at_flag_spin),
    reinterpret_cast<variant_fn>(at_relaxed_sum),
    reinterpret_cast<variant_fn>(at_seq_cst_ping_pong),
    reinterpret_cast<variant_fn>(at_shared_ptr_use),
    reinterpret_cast<variant_fn>(at_mutex_guard_style),
    reinterpret_cast<variant_fn>(at_atomic_ptr),
};
int main() {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
