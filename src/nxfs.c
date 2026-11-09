/* The user's own Switch files (nxfs.h). NCA3 as documented on switchbrew: header AES-XTS (header_key, the sector
 * number big-endian as tweak), sections AES-CTR (the section's 8-byte counter, then the NCA offset / 16), the key
 * from the key area (key_area_key_<kind>_<gen>) or a title key (a ticket in the NSP, or title.keys, under
 * titlekek_<gen>). NSO: LZ4 block segments. Our own implementation, as nxrecomp's runtime/nca.c. */
#define _FILE_OFFSET_BITS 64
#include "nxfs.h"
#include "crypto.h"
#include <ctype.h>
#include <stdlib.h>
#ifdef _WIN32
#include <io.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#endif

typedef struct { char name[64]; u8 v[32]; int n; } Key;
typedef struct { u8 rights[16], key[16]; } TitleKey;
typedef struct {
    char *path;
    u64 off;                    /* in the file (an NSP's NCAs are inside it) */
    u8 hdr[0xc00];              /* decrypted */
    u64 program_id;
} Nca;

struct NxFs {
    Key *keys;
    int nkeys;
    TitleKey *tkeys;
    int ntkeys;
    Nca *ncas;
    int nncas, nnsps;
};

/* ---------------------------------------------------------------------------------------------- files */
static FILE *open_file(const char *path) { return fopen(path, "rb"); }

static bool read_at(FILE *f, u64 off, void *dst, u64 n) {
#ifdef _WIN32
    if (_fseeki64(f, (long long)off, SEEK_SET)) return false;
#else
    if (fseeko(f, (off_t)off, SEEK_SET)) return false;
#endif
    return fread(dst, 1, n, f) == n;
}

static bool has_ext(const char *name, const char *ext) {
    size_t a = strlen(name), b = strlen(ext);
    if (a < b) return false;
    for (size_t i = 0; i < b; i++)
        if (tolower((unsigned char)name[a - b + i]) != tolower((unsigned char)ext[i])) return false;
    return true;
}

/* calls fn for each entry of dir (files and directories, not . or ..) */
static void list_dir(const char *dir, void (*fn)(void *ctx, const char *path, bool is_dir), void *ctx) {
    char path[1024];
#ifdef _WIN32
    snprintf(path, sizeof path, "%s/*", dir);
    struct _finddata_t fd;
    intptr_t h = _findfirst(path, &fd);
    if (h == -1) return;
    do {
        if (!strcmp(fd.name, ".") || !strcmp(fd.name, "..")) continue;
        snprintf(path, sizeof path, "%s/%s", dir, fd.name);
        fn(ctx, path, (fd.attrib & _A_SUBDIR) != 0);
    } while (!_findnext(h, &fd));
    _findclose(h);
#else
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        struct stat st;
        fn(ctx, path, !stat(path, &st) && S_ISDIR(st.st_mode));
    }
    closedir(d);
#endif
}

/* ---------------------------------------------------------------------------------------------- keys */
static int hexval(int c) {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

static int unhex(const char *s, u8 *out, int max) {
    int n = 0;
    while (s[0] && s[1] && n < max) {
        int a = hexval(s[0]), b = hexval(s[1]);
        if (a < 0 || b < 0) break;
        out[n++] = (u8)(a << 4 | b);
        s += 2;
    }
    return n;
}

/* "name = hex" lines; title.keys has rights id = title key. Earlier files win (a name already known is skipped). */
static bool load_keys(NxFs *fs, const char *path, bool title) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char ln[512];
    while (fgets(ln, sizeof ln, f)) {
        char *eq = strchr(ln, '=');
        if (!eq) continue;
        char name[128];
        int nn = 0;
        for (char *p = ln; p < eq && nn < 127; p++)
            if (*p != ' ' && *p != '\t') name[nn++] = (char)tolower((unsigned char)*p);
        name[nn] = 0;
        char *v = eq + 1;
        while (*v == ' ' || *v == '\t') v++;
        if (title) {
            TitleKey t;
            if (unhex(name, t.rights, 16) != 16 || unhex(v, t.key, 16) != 16) continue;
            fs->tkeys = realloc(fs->tkeys, (fs->ntkeys + 1) * sizeof *fs->tkeys);
            fs->tkeys[fs->ntkeys++] = t;
            continue;
        }
        Key k;
        snprintf(k.name, sizeof k.name, "%s", name);
        k.n = unhex(v, k.v, 32);
        if ((k.n != 16 && k.n != 32) || nxfs_key(fs, k.name, k.n)) continue;
        fs->keys = realloc(fs->keys, (fs->nkeys + 1) * sizeof *fs->keys);
        fs->keys[fs->nkeys++] = k;
    }
    fclose(f);
    return true;
}

const u8 *nxfs_key(NxFs *fs, const char *name, int n) {
    for (int i = 0; i < fs->nkeys; i++)
        if (!strcmp(fs->keys[i].name, name) && fs->keys[i].n == n) return fs->keys[i].v;
    return NULL;
}

/* ---------------------------------------------------------------------------------------------- PFS0 */
typedef struct { char name[64]; u64 off, size; } PfsFile;
typedef bool (*ReadFn)(void *ctx, u64 off, void *dst, u64 n);

/* the files of a PFS0 at `base` (offsets absolute, as `rd` reads); -1 if not a PFS0 */
static int pfs0_list(ReadFn rd, void *ctx, u64 base, PfsFile **out) {
    u8 h[16];
    if (!rd(ctx, base, h, 16) || memcmp(h, "PFS0", 4)) return -1;
    u32 nf, strsz;
    memcpy(&nf, h + 4, 4);
    memcpy(&strsz, h + 8, 4);
    if (nf > 100000 || strsz > 0x100000) return -1;
    u64 tab = 16 + (u64)nf * 0x18;
    u8 *t = malloc(tab + strsz + 1);
    if (!rd(ctx, base, t, tab + strsz)) { free(t); return -1; }
    t[tab + strsz] = 0;
    PfsFile *f = calloc(nf ? nf : 1, sizeof *f);
    for (u32 i = 0; i < nf; i++) {
        const u8 *e = t + 16 + i * 0x18;
        u64 o, s;
        u32 so;
        memcpy(&o, e, 8);
        memcpy(&s, e + 8, 8);
        memcpy(&so, e + 16, 4);
        f[i].off = base + tab + strsz + o;
        f[i].size = s;
        snprintf(f[i].name, sizeof f[i].name, "%s", so < strsz ? (const char *)t + tab + so : "");
    }
    free(t);
    *out = f;
    return (int)nf;
}

static bool file_rd(void *ctx, u64 off, void *dst, u64 n) { return read_at(ctx, off, dst, n); }

/* ---------------------------------------------------------------------------------------------- NCAs */
static void xts_decrypt(const u8 key[32], u8 *buf, u32 size, u64 sector) {
    Aes128 k1, k2;
    aes128_init(&k1, key);
    aes128_init(&k2, key + 16);
    for (u32 s = 0; s < size; s += 0x200, sector++) {
        u8 tw[16] = {0}, t[16];
        for (int i = 0; i < 8; i++) tw[15 - i] = (u8)(sector >> (8 * i));
        aes128_encrypt_block(&k2, tw, t);
        for (u32 b = 0; b < 0x200; b += 16) {
            u8 x[16];
            for (int i = 0; i < 16; i++) x[i] = buf[s + b + i] ^ t[i];
            aes128_decrypt_block(&k1, x, x);
            for (int i = 0; i < 16; i++) buf[s + b + i] = x[i] ^ t[i];
            int carry = t[15] >> 7;                   /* t *= x in GF(2^128), little-endian */
            for (int i = 15; i > 0; i--) t[i] = (u8)(t[i] << 1 | t[i - 1] >> 7);
            t[0] = (u8)(t[0] << 1);
            if (carry) t[0] ^= 0x87;
        }
    }
}

/* an NCA's header, kept if it is a program (content type 0) */
static void nca_add(NxFs *fs, const char *path, FILE *f, u64 off) {
    const u8 *hk = nxfs_key(fs, "header_key", 32);
    Nca n = {.off = off};
    if (!hk || !read_at(f, off, n.hdr, 0xc00)) return;
    xts_decrypt(hk, n.hdr, 0xc00, 0);
    if (memcmp(n.hdr + 0x200, "NCA3", 4) || n.hdr[0x205] != 0) return;
    memcpy(&n.program_id, n.hdr + 0x210, 8);
    n.path = malloc(strlen(path) + 1);
    strcpy(n.path, path);
    fs->ncas = realloc(fs->ncas, (fs->nncas + 1) * sizeof *fs->ncas);
    fs->ncas[fs->nncas++] = n;
}

/* the tickets in an NSP: rights id -> encrypted title key (common tickets: the key itself) */
static void ticket_add(NxFs *fs, const u8 *t, u64 n) {
    if (n < 0x2b0) return;
    u32 sig;
    memcpy(&sig, t, 4);
    u64 body = sig == 0x10004 ? 0x140 : sig == 0x10003 ? 0x240 : sig == 0x10005 ? 0x80 : 0;
    if (!body || n < body + 0x170) return;
    TitleKey k;
    memcpy(k.key, t + body + 0x40, 16);
    memcpy(k.rights, t + body + 0x160, 16);
    fs->tkeys = realloc(fs->tkeys, (fs->ntkeys + 1) * sizeof *fs->tkeys);
    fs->tkeys[fs->ntkeys++] = k;
}

static void nsp_add(NxFs *fs, const char *path) {
    FILE *f = open_file(path);
    if (!f) return;
    PfsFile *pf;
    int np = pfs0_list(file_rd, f, 0, &pf);
    if (np < 0) { fclose(f); return; }
    fs->nnsps++;
    for (int j = 0; j < np; j++)                    /* tickets first: the NCAs need them only when read */
        if (has_ext(pf[j].name, ".tik") && pf[j].size < 0x1000) {
            u8 t[0x1000];
            if (read_at(f, pf[j].off, t, pf[j].size)) ticket_add(fs, t, pf[j].size);
        }
    for (int j = 0; j < np; j++)
        if (has_ext(pf[j].name, ".nca") && !has_ext(pf[j].name, ".cnmt.nca")) nca_add(fs, path, f, pf[j].off);
    free(pf);
    fclose(f);
}

static void nca_file_add(NxFs *fs, const char *path) {
    if (has_ext(path, ".cnmt.nca")) return;
    FILE *f = open_file(path);
    if (!f) return;
    nca_add(fs, path, f, 0);
    fclose(f);
}

typedef struct { NxFs *fs; int depth; } Walk;

static void walk(void *ctx, const char *path, bool is_dir) {
    Walk *w = ctx;
    if (is_dir) {
        if (w->depth > 0) {
            Walk sub = {w->fs, w->depth - 1};
            list_dir(path, walk, &sub);
        }
    } else if (has_ext(path, ".nca")) nca_file_add(w->fs, path);
    else if (has_ext(path, ".nsp")) nsp_add(w->fs, path);
}

NxFs *nxfs_open(const char *const *dirs, int ndirs, char *err, size_t errn) {
    NxFs *fs = calloc(1, sizeof *fs);
    char path[1024];
    bool k = false;
    for (int i = 0; i < ndirs; i++) {
        snprintf(path, sizeof path, "%s/prod.keys", dirs[i]);
        k |= load_keys(fs, path, false);
        snprintf(path, sizeof path, "%s/title.keys", dirs[i]);
        load_keys(fs, path, true);
    }
    const char *home = getenv("USERPROFILE");
    if (!home) home = getenv("HOME");
    if (home) {                                     /* where the usual dumping tools put them */
        snprintf(path, sizeof path, "%s/.switch/prod.keys", home);
        k |= load_keys(fs, path, false);
        snprintf(path, sizeof path, "%s/.switch/title.keys", home);
        load_keys(fs, path, true);
    }
    if (!k) {
        snprintf(err, errn, "no prod.keys (dumped from your Switch) in the --files directories or ~/.switch");
        nxfs_close(fs);
        return NULL;
    }
    for (int i = 0; i < ndirs; i++) {               /* the directory, its subdirectories (firmware/<version>/) */
        Walk w = {fs, 2};
        list_dir(dirs[i], walk, &w);
    }
    return fs;
}

void nxfs_close(NxFs *fs) {
    if (!fs) return;
    for (int i = 0; i < fs->nncas; i++) free(fs->ncas[i].path);
    free(fs->ncas);
    free(fs->keys);
    free(fs->tkeys);
    free(fs);
}

int nxfs_nsp_count(NxFs *fs) { return fs->nnsps; }
int nxfs_nca_count(NxFs *fs) { return fs->nncas; }

/* the NCA's section key (key area slot 2, or the title key) */
static bool nca_key(NxFs *fs, const Nca *n, u8 key[16]) {
    const u8 *h = n->hdr;
    int gen = h[0x206] > h[0x220] ? h[0x206] : h[0x220];
    if (gen) gen--;
    static const u8 zero[16];
    char name[64];
    if (memcmp(h + 0x230, zero, 16)) {
        int i;
        for (i = 0; i < fs->ntkeys && memcmp(fs->tkeys[i].rights, h + 0x230, 16); i++) {}
        if (i == fs->ntkeys) { logf_(0, "keys: no ticket or title key for %016llx", (unsigned long long)n->program_id); return false; }
        snprintf(name, sizeof name, "titlekek_%02x", gen);
        const u8 *kek = nxfs_key(fs, name, 16);
        if (!kek) { logf_(0, "keys: prod.keys has no %s", name); return false; }
        aes128_ecb_decrypt1(kek, fs->tkeys[i].key, key);
    } else {
        static const char *kind[] = {"application", "ocean", "system"};
        snprintf(name, sizeof name, "key_area_key_%s_%02x", kind[h[0x207] < 3 ? h[0x207] : 0], gen);
        const u8 *kak = nxfs_key(fs, name, 16);
        if (!kak) { logf_(0, "keys: prod.keys has no %s", name); return false; }
        aes128_ecb_decrypt1(kak, h + 0x300 + 2 * 16, key);
    }
    return true;
}

typedef struct { FILE *f; u64 nca_off, start; u8 ctr_hi[8]; Aes128 aes; } SecReader;

/* bytes [off, off+n) of an AES-CTR section, off relative to the section */
static bool sec_rd(void *ctx, u64 off, void *dst, u64 n) {
    SecReader *s = ctx;
    u64 a = off & ~15ull, lead = off - a, m = (lead + n + 15) & ~15ull;
    u8 *tmp = malloc(m);
    if (!tmp || !read_at(s->f, s->nca_off + s->start + a, tmp, m)) { free(tmp); return false; }
    u8 iv[16];
    memcpy(iv, s->ctr_hi, 8);
    u64 blk = (s->start + a) >> 4;
    for (int j = 0; j < 8; j++) iv[15 - j] = (u8)(blk >> (8 * j));
    aes128_ctr(&s->aes, iv, tmp, m);
    memcpy(dst, tmp + lead, n);
    free(tmp);
    return true;
}

/* LZ4 block format */
static bool lz4_decode(const u8 *src, size_t sn, u8 *dst, size_t dn) {
    size_t i = 0, o = 0;
    while (i < sn) {
        u8 t = src[i++];
        size_t l = t >> 4;
        if (l == 15) for (u8 b = 255; b == 255 && i < sn;) { b = src[i++]; l += b; }
        if (i + l > sn || o + l > dn) return false;
        memcpy(dst + o, src + i, l);
        i += l; o += l;
        if (i >= sn) break;
        if (i + 2 > sn) return false;
        size_t back = src[i] | src[i + 1] << 8, m = t & 15;
        i += 2;
        if (m == 15) for (u8 b = 255; b == 255 && i < sn;) { b = src[i++]; m += b; }
        m += 4;
        if (!back || back > o || o + m > dn) return false;
        for (size_t j = 0; j < m; j++, o++) dst[o] = dst[o - back];
    }
    return o == dn;
}

u8 *nxfs_main_rodata(NxFs *fs, u64 program_id, int which, size_t *rn) {
    for (int i = 0; i < fs->nncas; i++) {
        Nca *n = &fs->ncas[i];
        if (n->program_id != program_id || which-- > 0) continue;
        u8 key[16];
        if (!nca_key(fs, n, key)) return NULL;
        for (int s = 0; s < 4; s++) {
            u32 a, b;
            memcpy(&a, n->hdr + 0x240 + s * 0x10, 4);
            memcpy(&b, n->hdr + 0x244 + s * 0x10, 4);
            const u8 *sh = n->hdr + 0x400 + s * 0x200;
            if (!b || sh[2] != 1 || sh[3] != 2 || sh[4] != 3) continue;    /* PFS0, SHA-256 hashed, AES-CTR: ExeFS */
            SecReader r = {.nca_off = n->off, .start = (u64)a * 0x200};
            for (int j = 0; j < 8; j++) r.ctr_hi[j] = sh[0x140 + 7 - j];
            aes128_init(&r.aes, key);
            u64 pfs_off;
            memcpy(&pfs_off, sh + 0x08 + 0x38, 8);
            if (!(r.f = open_file(n->path))) return NULL;
            PfsFile *pf;
            int np = pfs0_list(sec_rd, &r, pfs_off, &pf);
            u8 *out = NULL;
            for (int j = 0; j < np && !out; j++) {
                if (strcmp(pf[j].name, "main") || pf[j].size < 0x100) continue;
                u8 h[0x100];
                if (!sec_rd(&r, pf[j].off, h, sizeof h) || memcmp(h, "NSO0", 4)) break;
                u32 foff, size, csize, flags;
                memcpy(&flags, h + 0x0c, 4);
                memcpy(&foff, h + 0x20, 4);              /* .rodata: file offset, memory offset, size */
                memcpy(&size, h + 0x28, 4);
                memcpy(&csize, h + 0x64, 4);
                if (!(flags & 2)) csize = size;
                if (size > 0x10000000 || csize > 0x10000000 || foff + (u64)csize > pf[j].size) break;
                u8 *c = malloc(csize ? csize : 1);
                out = malloc(size ? size : 1);
                bool ok = c && out && sec_rd(&r, pf[j].off + foff, c, csize);
                if (ok && (flags & 2)) ok = lz4_decode(c, csize, out, size);
                else if (ok) memcpy(out, c, size);
                free(c);
                if (!ok) { free(out); out = NULL; logf_(0, "keys: %016llx's main could not be read", (unsigned long long)program_id); break; }
                *rn = size;
            }
            if (np > 0) free(pf);
            fclose(r.f);
            return out;
        }
        return NULL;
    }
    return NULL;
}
