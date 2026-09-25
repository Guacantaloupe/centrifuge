/* rtc demo: caller passes a call result straight into a callee that
 * dereferences its parameter; the return-through-call rule should then
 * recover the producer's return type as a pointer. */
static int slot_a = 7, slot_b = 9;
__attribute__((noinline)) int make(int i) {
    return (int)(long long)(i ? &slot_a : &slot_b);
}
__attribute__((noinline)) int use(int *p) { return *p; }
int main(int argc, char **argv) {
    int *q = (int *)(long long)make(argc);
    volatile int a = *q;
    return use(q) + a;
}
