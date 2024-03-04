#ifndef ECTF_CRYPTO_CHACHA
#define ECTF_CRYPTO_CHACHA

#include "wolfssl/wolfcrypt/chacha20_poly1305.h"

/******************************** MACRO DEFINITIONS ********************************/
#define CHACHA_IV_SIZE 12
#define CHACHA_TAG_SIZE 16

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt(
    const byte* plaintext, word32 len,
    byte* ciphertext,
    const byte* key,
    const byte* iv,
    const byte *auth, word32 auth_sz,
    byte* tag   // 16 byte tag buffer
);

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *           ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *           BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *           the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *           plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt(
    byte* plaintext, word32 len,
    const byte* ciphertext,
    const byte* key,
    const byte* iv,
    const byte *auth, word32 auth_sz,
    const byte* tag   // 16 byte tag buffer
);

#endif