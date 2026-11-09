/* LDN keys, found at run time in the user's own files, never compiled in: master_key_00 and the key generation
 * sources from prod.keys; the input keys and the challenge HMAC key in the firmware's ldn and es modules; the game's
 * passphrase and Pia key in its main. Each constant is recognised by its SHA-256 (ldnkeys.c): only the hashes are
 * here, so nothing works without the firmware (and the game) the user dumped. */
#ifndef LDNKEYS_H
#define LDNKEYS_H

#include "common.h"

typedef struct LdnKeys {
    u8 adv_kek[16];             /* the advertisement input key run through master_key_00's generation chain */
    u8 data_kek[16];            /* the same for the data input key */
    u8 challenge_hmac[32];
    char passphrase[128];       /* the game's, empty if no game was asked for */
    u8 pia_game_key[16];        /* the game's Pia key (16 characters) */
    bool have_pia_key;
} LdnKeys;

/* The directories searched when a tool gets no --files: next to it, then the workspace's (run from ldn-beacon/). */
extern const char *const ldn_default_dirs[];
extern const int ldn_ndefault_dirs;

/* Searches dirs (NULL / 0: the defaults) for prod.keys, title.keys, firmware NCAs and the game's NSPs (nxfs.h) and
 * derives the keks. game: "scarlet_violet", or NULL when the game's passphrase and Pia key are not needed. Prints what
 * is missing and returns false. */
bool ldn_keys_load(LdnKeys *k, const char *const *dirs, int ndirs, const char *game);

/* key = dec(kek, first 16 bytes of SHA-256(input)) */
void ldn_derive(const u8 kek[16], const void *input, size_t n, u8 key[16]);
/* the network's data key: derived from the server random + the game's passphrase (needs the passphrase loaded) */
void ldn_data_key(const LdnKeys *k, const u8 server_random[16], u8 key[16]);

#endif
