#ifndef ECTF_CRYPTO_CHACHA
#define ECTF_CRYPTO_CHACHA

#include "wolfssl/wolfcrypt/chacha20_poly1305.h"

/******************************** MACRO DEFINITIONS ********************************/
#define CHACHA_IV_SIZE 12
#define CHACHA_TAG_SIZE 16

/******************************** FUNCTION PROTOTYPES ********************************/

/** @brief Encrypts plaintext using a symmetric cipher and given IV + auth data
 * Writes into the ciphertext buffer and 16 byte tag buffer 
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt.
  * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 * @param key A pointer to a buffer of length 32 bytes containing
 *          the key to use for encryption
 * @param iv A pointer to the buffer containing the unique IV
 * @param auth A pointer to the additional data used for authenticated encryption
 * @param auth_sz The size of the auth data
 * @param tag Buffer for the tag
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

/** @brief Decrypts ciphertext using a symmetric cipher and given IV + auth data
 * Writes into the ciphertext buffer 
 *
 * @param plaintext A pointer to a buffer for the plaintext
 * @param len The length of the ciphertext to decrypt.
 * @param ciphertext A pointer to a buffer containing the ciphertext
 * @param key A pointer to a buffer of length 32 bytes containing the key to use for decryption
 * @param iv A pointer to the buffer containing the unique IV
 * @param auth A pointer to the additional data to verify for authenticated encryption
 * @param auth_sz The size of the auth data
 * @param tag Pointer to the buffer containing the tag
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
