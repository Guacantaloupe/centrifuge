/* 33. C++ STL Containers & Algorithms family. */
#include <cstdint>
#include <cstddef>
#include <vector>
#include <map>
#include <string>
#include <optional>
#include <algorithm>
#include <numeric>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(st_vector_push);
int st_vector_push(int n) {
    MARK(st_vector_push);
    std::vector<int> v;
    for (int i = 0; i < n; i++) v.push_back(i * i);
    return (int)v.size();
}
TAG(st_vector_accumulate);
int st_vector_accumulate(const int *arr, int n) {
    MARK(st_vector_accumulate);
    std::vector<int> v(arr, arr + n);
    return std::accumulate(v.begin(), v.end(), 0);
}
TAG(st_vector_sort_unique);
int st_vector_sort_unique(int *arr, int n) {
    MARK(st_vector_sort_unique);
    std::vector<int> v(arr, arr + n);
    std::sort(v.begin(), v.end());
    auto it = std::unique(v.begin(), v.end());
    return (int)(it - v.begin());
}
TAG(st_vector_lower_bound);
int st_vector_lower_bound(const int *arr, int n, int key) {
    MARK(st_vector_lower_bound);
    std::vector<int> v(arr, arr + n);
    auto it = std::lower_bound(v.begin(), v.end(), key);
    return it == v.end() ? -1 : (int)(it - v.begin());
}
TAG(st_map_insert_lookup);
int st_map_insert_lookup(int n, int key) {
    MARK(st_map_insert_lookup);
    std::map<int, int> m;
    for (int i = 0; i < n; i++) m[i] = i * 3;
    auto it = m.find(key);
    return it == m.end() ? -1 : it->second;
}
TAG(st_map_iterate);
long long st_map_iterate(int n) {
    MARK(st_map_iterate);
    std::map<int, int> m;
    for (int i = 0; i < n; i++) m[n - i] = i;
    long long s = 0;
    for (auto &kv : m) s += kv.first + kv.second;
    return s;
}
TAG(st_optional_chain);
int st_optional_chain(int x) {
    MARK(st_optional_chain);
    std::optional<int> o;
    if (x > 0) o = x * 2;
    if (o) return *o + 1;
    return -1;
}
TAG(st_optional_or);
int st_optional_or(int x) {
    MARK(st_optional_or);
    std::optional<int> a, b;
    if (x & 1) a = x;
    if (x & 2) b = x + 1;
    return a.value_or(b.value_or(-7));
}
TAG(st_string_ops);
int st_string_ops(int n) {
    MARK(st_string_ops);
    std::string s = "ab";
    for (int i = 0; i < n; i++) s += (i & 1) ? 'x' : 'y';
    int count = 0;
    for (char c : s)
        if (c == 'x') count++;
    return count + (int)s.size();
}
TAG(st_count_if);
int st_count_if(const int *arr, int n) {
    MARK(st_count_if);
    std::vector<int> v(arr, arr + n);
    return (int)std::count_if(v.begin(), v.end(), [](int x) { return x > 0; });
}
TAG(st_transform);
int st_transform(const int *arr, int n) {
    MARK(st_transform);
    std::vector<int> v(arr, arr + n), out(n);
    std::transform(v.begin(), v.end(), out.begin(), [](int x) { return x * x + 1; });
    return out.empty() ? 0 : out.back();
}
TAG(st_minmax);
int st_minmax(int a, int b, int c) {
    MARK(st_minmax);
    return std::max(std::min(a, b), std::min(b, c));
}
TAG(st_heap_select);
int st_heap_select(int *arr, int n, int k) {
    MARK(st_heap_select);
    std::vector<int> v(arr, arr + n);
    std::make_heap(v.begin(), v.end());
    for (int i = 0; i < k && !v.empty(); i++) std::pop_heap(v.begin(), v.end() - i);
    return k < n ? arr[k] : 0;
}
TAG(st_deque_sim);
int st_deque_sim(int n) {
    MARK(st_deque_sim);
    std::vector<int> dq;
    for (int i = 0; i < n; i++) {
        if (i & 1) dq.insert(dq.begin(), i);
        else dq.push_back(i);
    }
    long long s = 0;
    while (!dq.empty()) { s += dq.back(); dq.pop_back(); }
    return (int)(s & 0x7fffffff);
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    reinterpret_cast<variant_fn>(st_vector_push),
    reinterpret_cast<variant_fn>(st_vector_accumulate),
    reinterpret_cast<variant_fn>(st_vector_sort_unique),
    reinterpret_cast<variant_fn>(st_vector_lower_bound),
    reinterpret_cast<variant_fn>(st_map_insert_lookup),
    reinterpret_cast<variant_fn>(st_map_iterate),
    reinterpret_cast<variant_fn>(st_optional_chain),
    reinterpret_cast<variant_fn>(st_optional_or),
    reinterpret_cast<variant_fn>(st_string_ops),
    reinterpret_cast<variant_fn>(st_count_if),
    reinterpret_cast<variant_fn>(st_transform),
    reinterpret_cast<variant_fn>(st_minmax),
    reinterpret_cast<variant_fn>(st_heap_select),
    reinterpret_cast<variant_fn>(st_deque_sim),
};
int main() {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
