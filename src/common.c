#include "common.h"
#include <stdarg.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
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
