#ifdef _WIN32
#define _CRT_RAND_S
#endif
#include "common.h"
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/random.h>
#include <unistd.h>
#endif

int log_level = 1;

void logf_(int level, const char *fmt, ...) {
    if (level > log_level) return;
    char t[16];
    time_t now = time(NULL);
    strftime(t, sizeof t, "%H:%M:%S", localtime(&now));
    printf("[%s] ", t);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

u64 now_ms(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000 + (u64)ts.tv_nsec / 1000000;
#endif
}

u64 now_us(void) {
#ifdef _WIN32
    static LARGE_INTEGER f;
    LARGE_INTEGER c;
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (u64)(c.QuadPart / f.QuadPart * 1000000 + c.QuadPart % f.QuadPart * 1000000 / f.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000 + (u64)ts.tv_nsec / 1000;
#endif
}

void random_bytes(void *p, size_t n) {
    u8 *b = (u8 *)p;
#ifdef _WIN32
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        rand_s(&v);
        b[i] = (u8)v;
    }
#else
    while (n) {
        ssize_t k = getrandom(b, n, 0);
        if (k <= 0) continue;
        b += k;
        n -= (size_t)k;
    }
#endif
}
