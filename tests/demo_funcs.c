int compute(int a, int b) {
    int x = a * 4 + b;
    if (x > 100) return x - 100;
    return x;
}

int max3(int a, int b, int c) {
    int m = a;
    if (b > m) m = b;
    if (c > m) m = c;
    return m;
}

int absdiff(int a, int b) {
    int d = a - b;
    if (d < 0) d = -d;
    return d;
}
