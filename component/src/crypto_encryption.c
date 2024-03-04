#include "crypto_encryption.h"

#include <stdint.h>
#include <string.h>

int encrypt(
    const byte *plaintext, word32 len,
    byte *ciphertext,
    const byte *key, // 32 byte key
    const byte *iv, // 12 byte IV
    const byte *auth, word32 auth_sz, // Arbitrary length additional data
    byte *tag // 16 byte tag buffer
)
{
    int result = wc_ChaCha20Poly1305_Encrypt(key, iv, auth, auth_sz, plaintext, len, ciphertext, tag);
    if (result != 0)
        return result; // Report error
    return 0;
}

int decrypt(
    byte *plaintext, word32 len,
    const byte *ciphertext,
    const byte *key,
    const byte *iv,
    const byte *auth, word32 auth_sz, // Arbitrary length additional data
    const byte *tag // 16 byte tag buffer
)
{
    int result = wc_ChaCha20Poly1305_Decrypt(key, iv, auth, auth_sz, ciphertext, len, tag, plaintext);
    if (result != 0)
        return result; // Report error
    return 0;
}