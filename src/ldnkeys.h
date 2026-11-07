/* LDN keys. Loaded from key files at run time (prod.keys and ldn.txt: "name = value" lines), never compiled in. */
#ifndef LDNKEYS_H
#define LDNKEYS_H

#include "common.h"

typedef struct LdnKeys {
    u8 adv_kek[16];             /* the advertisement input key run through master_key_00's generation chain */
    u8 data_kek[16];            /* the same for the data input key */
    u8 challenge_hmac[32];
    char passphrase[128];       /* the game's (ldn_passphrase_*), empty if none was given */
} LdnKeys;

/* Reads every file (later files override earlier names) and derives the keks. passphrase_name selects the game's
 * passphrase line (e.g. "ldn_passphrase_scarlet_violet"), NULL for none. Prints what is missing and returns false. */
bool ldn_keys_load(LdnKeys *k, const char *const *files, int nfiles, const char *passphrase_name);

/* key = dec(kek, first 16 bytes of SHA-256(input)) */
void ldn_derive(const u8 kek[16], const void *input, size_t n, u8 key[16]);

#endif
