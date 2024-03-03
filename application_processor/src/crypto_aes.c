#include "crypto_aes.h"

#include <stdint.h>
#include <string.h>


/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric AES cipher with Gallois-Counter Mode
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
) {
    Aes ctx; // Context for encryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for encryption
    result = wc_AesGcmSetKey(&ctx, key, key_sz);
    if (result != 0)
        return result; // Report error

    // Encrypt each block
    result = wc_AesGcmEncrypt(&ctx, ciphertext, plaintext, len, iv, iv_sz, tag, GCM_TAG_SIZE, auth, auth_sz);
    if (result != 0)
        return result; // Report error
    return 0;
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
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
) {
    Aes ctx; // Context for decryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for decryption
    result = wc_AesGcmSetKey(&ctx, key, key_sz);
    if (result != 0)
        return result; // Report error

    result = wc_AesGcmDecrypt(&ctx, plaintext, ciphertext, len, iv, iv_sz, tag, GCM_TAG_SIZE, auth, auth_sz);
    if (result != 0)
        return result; // Report error
    return 0;
}