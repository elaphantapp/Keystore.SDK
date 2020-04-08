
#ifndef __BIP39_H__
#define __BIP39_H__


#include <stdbool.h>
#include <stdint.h>

#define BIP39_WORDLIST_COUNT 2048

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \~English
 * Generates a random mnemonic phrase with the given strength in bits.
 *
 * @param
 *      strength    [in] mnemonic strength in bits. Must be a multiple of 32 between 128 and 256.
 * @param
 *      language    [in] words list language, such as english, chinese etc.
 * @param
 *      mnemonic    [out] mnemonic phrase.
 *
 * @return
 *      mnemonic length if succeeded or if menmonic is NULL, or negative if failed.
 */
int generateMnemonic(int strength, const char* language, char* mnemonic);

/**
 * \~English
 * Check the mnemonic is valid.
 *
 * @param
 *      mnemonic    [in] mnemonic phrase.
 *
 * @return
 *      true if valid, or false if invalid.
 */
bool checkMnemonic(const char* mnemonic);

/**
 * \~English
 * Get seed from mnemonic.
 *
 * @param
 *      mnemonic    [in] mnemonic phrase.
 * @param
 *      passphrase  [in] passphrase of mnemonic, may be nullptr or null string.
 * @param
 *      seed        [in] seed from mnemonic and passphrase.
 *
 * @return
 *      none.
 */
void mnemonicToSeed(const char* mnemonic, char* passphrase, uint8_t seed[64]);


#ifdef __cplusplus
} // extern "C"
#endif

#endif //__BIP39_H__
