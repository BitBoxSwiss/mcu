#include <string.h>
#include "bip39.h"
#include "hmac.h"
#include "sha2.h"
#include "random.h"
#include "pbkdf2.h"
#include "bip39_english.h"
#include "commander.h"


char *mnemonic_from_data(const uint8_t *data, int len)
{
	if (len % 4 || len < 16 || len > 32) {
		return 0;
	}

	uint8_t bits[32 + 1];

	sha256_Raw(data, len, bits);
	bits[len] = bits[0];
	memcpy(bits, data, len);

	int mlen = len * 3 / 4;
	static char mnemo[24 * 10];

	int i, j, idx;
	char *p = mnemo;
	for (i = 0; i < mlen; i++) {
		idx = 0;
		for (j = 0; j < 11; j++) {
			idx <<= 1;
			idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
		}
		strcpy(p, wordlist[idx]);
		p += strlen(wordlist[idx]);
		*p = (i < mlen - 1) ? ' ' : 0;
		p++;
	}

	return mnemo;
}

int mnemonic_check(const char *mnemonic)
{
	if (!mnemonic) {
        fill_report("seed", "Empty mnemonic.", ERROR);
		return 0;
	}

	uint32_t i, n;

	i = 0; n = 0;
	while (mnemonic[i]) {
		if (mnemonic[i] == ' ') {
			n++;
		}
		i++;
	}
	n++;
	// check number of words
	if (n != 12 && n != 18 && n != 24) {
        fill_report("seed", "Mnemonic must have 12, 18, or 24 words.", ERROR);
		return 0;
	}

	char current_word[10];
	uint32_t j, k, ki, bi;
	uint8_t bits[32 + 1];
	memset(bits, 0, sizeof(bits));
	i = 0; bi = 0;
	while (mnemonic[i]) {
		j = 0;
		while (mnemonic[i] != ' ' && mnemonic[i] != 0) {
			if (j >= sizeof(current_word)) {
                fill_report("seed", "Word not in bip39 wordlist.", ERROR);
				return 0;
			}
			current_word[j] = mnemonic[i];
			i++; j++;
		}
		current_word[j] = 0;
		if (mnemonic[i] != 0) i++;
		k = 0;
		for (;;) {
			if (!wordlist[k]) { // word not found
                fill_report("seed", "Word not in bip39 wordlist.", ERROR);
				return 0;
			}
			if (strcmp(current_word, wordlist[k]) == 0) { // word found on index k
				for (ki = 0; ki < 11; ki++) {
					if (k & (1 << (10 - ki))) {
						bits[bi / 8] |= 1 << (7 - (bi % 8));
					}
					bi++;
				}
				break;
			}
			k++;
		}
	}
	if (bi != n * 11) {
        fill_report("seed", "Mnemonic check error. [0]", ERROR);
		return 0;
	}
	bits[32] = bits[n * 4 / 3];
	sha256_Raw(bits, n * 4 / 3, bits);
	if (n == 12) {
		return (bits[0] & 0xF0) == (bits[32] & 0xF0); // compare first 4 bits
	} else
	if (n == 18) {
		return (bits[0] & 0xFC) == (bits[32] & 0xFC); // compare first 6 bits
	} else
	if (n == 24) {
		return bits[0] == bits[32]; // compare 8 bits
	}
   
    fill_report("seed", "Invalid mnemonic: checksum error.", ERROR);
    return 0;
}

void mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t seed[512 / 8], void (*progress_callback)(uint32_t current, uint32_t total))
{
	static uint8_t salt[8 + 256 + 4];
	int saltlen = strlen(passphrase);
	memcpy(salt, "mnemonic", 8);
	memcpy(salt + 8, passphrase, saltlen);
	saltlen += 8;
	pbkdf2_hmac_sha512((const uint8_t *)mnemonic, strlen(mnemonic), salt, saltlen, BIP39_PBKDF2_ROUNDS, seed, 512 / 8, progress_callback);
}

const char **mnemonic_wordlist(void)
{
	return wordlist;
}
