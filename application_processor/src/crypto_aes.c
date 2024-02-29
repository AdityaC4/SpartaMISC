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
int encrypt_aesgcm(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext, uint8_t *iv, uint8_t *tag) {
    Aes ctx; // Context for encryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for encryption
    result = wc_AesGcmSetKey(&ctx, key, KEY_SIZE);
    if (result != 0)
        return result; // Report error

    // Encrypt each block
    result = wc_AesGcmEncrypt(&ctx, ciphertext, plaintext, len, iv, BLOCK_SIZE, tag, BLOCK_SIZE, NULL, 0);
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
int decrypt_aesgcm(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext, uint8_t *iv, uint8_t *tag) {
    Aes ctx; // Context for decryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for decryption
    result = wc_AesGcmSetKey(&ctx, key, KEY_SIZE);
    if (result != 0)
        return result; // Report error

    result = wc_AesGcmDecrypt(&ctx, plaintext, ciphertext, len, iv, BLOCK_SIZE, tag, BLOCK_SIZE, NULL, 0);
    if (result != 0)
        return result; // Report error
    return 0;
}