
#include "bip39.h"
#include "BRCrypto.h"
#include <stdio.h>
#include <assert.h>
#include "random.h"
#include "BRInt.h"
#include "words/chinese_tr.h"
#include "words/chinese_zh.h"
#include "words/english.h"
#include "words/french.h"
#include "words/italian.h"
#include "words/japanese.h"
#include "words/korean.h"
#include "words/spanish.h"

#define LANGUAGE_TYPE_COUNT 8
const char* languages[LANGUAGE_TYPE_COUNT] = {
    "english",
    "chinese",
    "chinese_tr",
    "french",
    "italian",
    "japanese",
    "korean",
    "spanish"
};

static const char* const* getWordList(const char* language)
{
    if (!strcmp(language, languages[0])) {
        return wordlist_english;
    }
    else if (!strcmp(language, languages[1])) {
        return wordlist_chinese_zh;
    }
    else if (!strcmp(language, languages[2])) {
        return wordlist_chinese_tr;
    }
    else if (!strcmp(language, languages[3])) {
        return wordlist_french;
    }
    else if (!strcmp(language, languages[4])) {
        return wordlist_italian;
    }
    else if (!strcmp(language, languages[5])) {
        return wordlist_japanese;
    }
    else if (!strcmp(language, languages[6])) {
        return wordlist_korean;
    }
    else if (!strcmp(language, languages[7])) {
        return wordlist_spanish;
    }
    else {
        printf("not support language %s\n", language);
        return NULL;
    }
}

static size_t BRBIP39Encode(char *phrase, size_t phraseLen, const char *wordList[], const uint8_t *data, size_t dataLen)
{
    uint32_t x;
    uint8_t buf[dataLen + 32];
    const char *word;
    size_t i, len = 0;

    assert(wordList != NULL);
    assert(data != NULL || dataLen == 0);
    assert(dataLen > 0 && (dataLen % 4) == 0);
    if (! data || (dataLen % 4) != 0) return 0; // data length must be a multiple of 32 bits

    memcpy(buf, data, dataLen);
    BRSHA256(&buf[dataLen], data, dataLen); // append SHA256 checksum

    for (i = 0; i < dataLen*3/4; i++) {
        x = UInt32GetBE(&buf[i*11/8]);
        word = wordList[(x >> (32 - (11 + ((i*11) % 8)))) % BIP39_WORDLIST_COUNT];
        if (i > 0 && phrase && len < phraseLen) phrase[len] = ' ';
        if (i > 0) len++;
        if (phrase && len < phraseLen) strncpy(&phrase[len], word, phraseLen - len);
        len += strlen(word);
    }

    var_clean(&word);
    var_clean(&x);
    mem_clean(buf, sizeof(buf));
    return (! phrase || len + 1 <= phraseLen) ? len + 1 : 0;
}

// returns number of bytes written to data, or dataLen needed if data is NULL
static size_t BRBIP39Decode(uint8_t *data, size_t dataLen, const char *wordList[], const char *phrase)
{
    uint32_t x, y, count = 0, idx[24], i;
    uint8_t b = 0, hash[32];
    const char *word = phrase;
    size_t r = 0;

    assert(wordList != NULL);
    assert(phrase != NULL);

    while (word && *word && count < 24) {
        for (i = 0, idx[count] = INT32_MAX; i < BIP39_WORDLIST_COUNT; i++) { // not fast, but simple and correct
            if (strncmp(word, wordList[i], strlen(wordList[i])) != 0 ||
                (word[strlen(wordList[i])] != ' ' && word[strlen(wordList[i])] != '\0')) continue;
            idx[count] = i;
            break;
        }

        if (idx[count] == INT32_MAX) break; // phrase contains unknown word
        count++;
        word = strchr(word, ' ');
        if (word) word++;
    }

    if ((count % 3) == 0 && (! word || *word == '\0')) { // check that phrase has correct number of words
        uint8_t buf[(count*11 + 7)/8];

        for (i = 0; i < (count*11 + 7)/8; i++) {
            x = idx[i*8/11];
            y = (i*8/11 + 1 < count) ? idx[i*8/11 + 1] : 0;
            b = ((x*BIP39_WORDLIST_COUNT + y) >> ((i*8/11 + 2)*11 - (i + 1)*8)) & 0xff;
            buf[i] = b;
        }

        BRSHA256(hash, buf, count*4/3);

        if (b >> (8 - count/3) == (hash[0] >> (8 - count/3))) { // verify checksum
            r = count*4/3;
            if (data && r <= dataLen) memcpy(data, buf, r);
        }

        mem_clean(buf, sizeof(buf));
    }

    var_clean(&b);
    var_clean(&x, &y);
    mem_clean(idx, sizeof(idx));
    return (! data || r <= dataLen) ? r : 0;
}

int generateMnemonic(int strength, const char* language,  char* mnemonic)
{
    if (strength % 32 || strength < 128 || strength > 256 || !language) {
        printf("invalid argument!\n");
        return -1;
    }

    const char* const* wordList = getWordList(language);
    if (wordList == NULL) {
        return -1;
    }

    size_t len = strength / 8;
    uint8_t seed[len];
    for (size_t i = 0; i < len; i++) {
        seed[i] = getRandomByte();
    }

    size_t phraselen = BRBIP39Encode(NULL, 0, (const char**)wordList, seed, len);
    if (mnemonic != NULL) {
        phraselen = BRBIP39Encode(mnemonic, phraselen, (const char**)wordList, seed, len);
    }

    return phraselen;
}

bool checkMnemonic(const char* mnemonic)
{
    if (!mnemonic) return false;

    for (int i = 0; i < LANGUAGE_TYPE_COUNT; i++) {
        const char* const* wordList = getWordList(languages[i]);
        if (BRBIP39Decode(NULL, 0, (const char**)wordList, mnemonic) > 0) return true;
    }

    return false;
}

void mnemonicToSeed(const char* mnemonic, char* passphrase, uint8_t seed[64])
{
    char salt[strlen("mnemonic") + (passphrase ? strlen(passphrase) : 0) + 1];

    assert(mnemonic != NULL);
    if (!mnemonic) return;

    strcpy(salt, "mnemonic");
    if (passphrase) strcpy(salt + strlen("mnemonic"), passphrase);
    BRPBKDF2(seed, 64, BRSHA512, 512/8, mnemonic, strlen(mnemonic), salt, strlen(salt), 2048);
    mem_clean(salt, sizeof(salt));
}
