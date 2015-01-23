#ifndef __BIP39_H__
#define __BIP39_H__

#include <stdint.h>

#define BIP39_PBKDF2_ROUNDS 2048

char *mnemonic_from_data(const uint8_t *data, int len);
int mnemonic_check(const char *mnemonic);
void mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t seed[512 / 8], void (*progress_callback)(uint32_t current, uint32_t total));
const char **mnemonic_wordlist(void);

#endif
