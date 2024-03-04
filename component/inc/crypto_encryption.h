#ifndef ECTF_CRYPTO_CHACHA
#define ECTF_CRYPTO_CHACHA

#include "wolfssl/wolfcrypt/chacha20_poly1305.h"

/******************************** MACRO DEFINITIONS ********************************/
#define CHACHA_IV_SIZE 12
#define CHACHA_TAG_SIZE 16

/******************************** FUNCTION PROTOTYPES ********************************/

int encrypt(
    const byte* plaintext, word32 len,
    byte* ciphertext,
    const byte* key,
    const byte* iv,
    const byte *auth, word32 auth_sz,
    byte* tag   // 16 byte tag buffer
);

int decrypt(
    byte* plaintext, word32 len,
    const byte* ciphertext,
    const byte* key,
    const byte* iv,
    const byte *auth, word32 auth_sz,
    const byte* tag   // 16 byte tag buffer
);

#endif