int fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

int sum_array(int* a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}

int main() {
    int arr[4] = {1, 2, 3, 4};
    return fib(5) + sum_array(arr, 4);
}
