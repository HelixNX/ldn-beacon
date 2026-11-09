/* The user's own Switch files, read in place: prod.keys / title.keys, the game's NSPs and the firmware's NCAs,
 * decrypted as they are read (nothing is extracted). Only what the beacon needs: a program's ExeFS `main` (NSO),
 * its read-only segment decompressed. Portable (Windows and Linux); the AES is crypto.c's. */
#ifndef NXFS_H
#define NXFS_H

#include "common.h"

typedef struct NxFs NxFs;

/* Searches each directory for prod.keys and title.keys (then ~/.switch), NSPs, and NCAs (in the directory, its
 * subdirectories, and firmware/ with its subdirectories). NULL (reason in err) without prod.keys. */
NxFs *nxfs_open(const char *const *dirs, int ndirs, char *err, size_t errn);
void nxfs_close(NxFs *fs);

/* a prod.keys value of n bytes, NULL if absent */
const u8 *nxfs_key(NxFs *fs, const char *name, int n);

/* the read-only segment (.rodata) of the ExeFS `main` of the which-th program NCA (0, 1, ...) with this program id;
 * malloc'd, NULL when there are no more (or it cannot be read: the reason is logged) */
u8 *nxfs_main_rodata(NxFs *fs, u64 program_id, int which, size_t *n);

/* counts, for messages */
int nxfs_nsp_count(NxFs *fs);
int nxfs_nca_count(NxFs *fs);

#endif
