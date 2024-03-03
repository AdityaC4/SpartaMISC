#ifndef ECTF_CRYPTO_AES
#define ECTF_CRYPTO_AES

#include "wolfssl/wolfcrypt/aes.h"

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 32
#define GCM_TAG_SIZE 16
#define GCM_IV_SIZE 12

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
int encrypt_aesgcm(
    const byte* plaintext, word32 len,
    byte* ciphertext,
    const byte* key, word32 key_sz,
    const byte* iv, word32 iv_sz,
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
int decrypt_aesgcm(
    byte* plaintext, word32 len,
    const byte* ciphertext,
    const byte* key, word32 key_sz,
    const byte* iv, word32 iv_sz,
    const byte *auth, word32 auth_sz,
    const byte* tag   // 16 byte tag buffer
);

#endif