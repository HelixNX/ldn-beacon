/* Bounds-checked byte reader and writer. Every parse of a frame from the air goes through these: anyone in radio
 * range can send the beacon anything, so nothing indexes a received buffer directly. A failed read sets err, returns
 * zero (copies zero-fill) and every later call fails too, so a parser checks err once at the end. */
#ifndef RD_H
#define RD_H

#include "common.h"

typedef struct Rd { const u8 *p; size_t n, off; bool err; } Rd;
typedef struct Wr { u8 *p; size_t n, off; bool err; } Wr;

static inline Rd rd_init(const void *p, size_t n) { Rd r = {(const u8 *)p, n, 0, false}; return r; }
static inline Wr wr_init(void *p, size_t n) { Wr w = {(u8 *)p, n, 0, false}; return w; }

static inline const u8 *rd_take(Rd *r, size_t k) {
    if (r->err || k > r->n - r->off) { r->err = true; return NULL; }
    const u8 *q = r->p + r->off;
    r->off += k;
    return q;
}
static inline size_t rd_left(const Rd *r) { return r->err ? 0 : r->n - r->off; }
static inline void rd_skip(Rd *r, size_t k) { (void)rd_take(r, k); }
static inline void rd_copy(Rd *r, void *dst, size_t k) {
    const u8 *q = rd_take(r, k);
    if (q) memcpy(dst, q, k); else memset(dst, 0, k);
}
static inline u8 rd_u8(Rd *r) { const u8 *q = rd_take(r, 1); return q ? q[0] : 0; }
static inline u16 rd_be16(Rd *r) { const u8 *q = rd_take(r, 2); return q ? (u16)(q[0] << 8 | q[1]) : 0; }
static inline u32 rd_be32(Rd *r) {
    const u8 *q = rd_take(r, 4);
    return q ? (u32)q[0] << 24 | (u32)q[1] << 16 | (u32)q[2] << 8 | q[3] : 0;
}
static inline u64 rd_be64(Rd *r) { u64 h = rd_be32(r); return h << 32 | rd_be32(r); }
static inline u16 rd_le16(Rd *r) { const u8 *q = rd_take(r, 2); return q ? (u16)(q[1] << 8 | q[0]) : 0; }

static inline u8 *wr_take(Wr *w, size_t k) {
    if (w->err || k > w->n - w->off) { w->err = true; return NULL; }
    u8 *q = w->p + w->off;
    w->off += k;
    return q;
}
static inline void wr_bytes(Wr *w, const void *src, size_t k) { u8 *q = wr_take(w, k); if (q) memcpy(q, src, k); }
static inline void wr_zero(Wr *w, size_t k) { u8 *q = wr_take(w, k); if (q) memset(q, 0, k); }
static inline void wr_u8(Wr *w, u8 v) { u8 *q = wr_take(w, 1); if (q) q[0] = v; }
static inline void wr_be16(Wr *w, u16 v) { u8 *q = wr_take(w, 2); if (q) { q[0] = (u8)(v >> 8); q[1] = (u8)v; } }
static inline void wr_be32(Wr *w, u32 v) {
    u8 *q = wr_take(w, 4);
    if (q) { q[0] = (u8)(v >> 24); q[1] = (u8)(v >> 16); q[2] = (u8)(v >> 8); q[3] = (u8)v; }
}
static inline void wr_be64(Wr *w, u64 v) { wr_be32(w, (u32)(v >> 32)); wr_be32(w, (u32)v); }

#endif
