// Synthetic C++ sample: virtual dispatch through a base pointer so the
// object graph recovery has a vtable slot to resolve at the indirect call.
#include <cstdint>
#include <cstdio>

struct Shape {
    virtual ~Shape() {}
    virtual uint64_t area() const { return 0; }
    uint32_t tag;
};

struct Square : Shape {
    uint64_t side;
    uint64_t area() const override { return side * side; }
};

static __attribute__((noinline)) uint64_t measure(const Shape *s) {
    return s->area();
}

int main() {
    Square sq;
    sq.tag = 7;
    sq.side = 5;
    std::printf("%llu\n", (unsigned long long)measure(&sq));
    return 0;
}
