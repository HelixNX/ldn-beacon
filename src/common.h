/* Shared types and logging. */
#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;

/* 0 always, 1 normal, 2 every packet */
extern int log_level;
void logf_(int level, const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

/* milliseconds from an arbitrary start */
u64 now_ms(void);
/* microseconds from an arbitrary start */
u64 now_us(void);
/* from the OS's cryptographic generator */
void random_bytes(void *p, size_t n);

#define IP_FMT "%u.%u.%u.%u"
#define IP_ARG(ip) (ip)[0], (ip)[1], (ip)[2], (ip)[3]

#endif
