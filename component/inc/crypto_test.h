#ifndef ECTF_CRYPTO_TEST_H
#define ECTF_CRYPTO_TEST_H

#include "ectf_params.h"
#include "ectf_keys.h"
#include "host_messaging.h"

#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/integer.h"
#include "wolfssl/wolfcrypt/random.h"

#define ECC_CURVE ECC_SECP256R1
#define ECC_KEY_LEN 32

#define COMPR_KEY_SIZE 33
#define COMPR_KEY_BUFSIZE 36 // To avoid struct padding issues, just in case

#define PUBKEY_BUF_LEN ECC_BUFSIZE
#define PUBKEY_LEN ECC_MAXSIZE + 1

#define POINT_SIZE 32
#define CERT_DATA_SIZE 2 * POINT_SIZE + 4
#define ECC_SIG_SIZE 72

#define SHARED_KEY_SIZE 32

#define AP_TAG 0xffffffff

#define IS_COMPONENT 1

// All of these should be smaller than MAX_I2C_MESSAGE_LEN-1

typedef struct cert_data {
    byte pubkey_x[32];
    byte pubkey_y[32];
    word32 tag;
} cert_data;

typedef struct hello {
    // Compressed ANSI X9.63 keys
    byte pubkey[COMPR_KEY_BUFSIZE];
    byte dh_pubkey[COMPR_KEY_BUFSIZE];
} hello;

typedef struct signed_hello {
    hello hi;
    byte hello_sig[ECC_SIG_SIZE];
    word32 hello_sig_size;
} signed_hello;

// Hellos shared between AP and component with certificate and DH key info
typedef struct signed_hello_with_cert {
    signed_hello sh;

    byte cert_sig[ECC_SIG_SIZE];
    word32 cert_sig_size;
} signed_hello_with_cert;

// Response from the Component to the AP: contains the same data except with a
// signed challenge (DH pubkey) typedef struct signed_hello_with_cert_and_chal {
// 	signed_hello_with_cert shc;

// 	byte chal_sig[ECC_SIG_SIZE];
// 	word32 chal_sig_size;
// } signed_hello_with_cert_and_chal;

// Sent back by the AP to the Component as AP's challenge-response to finish the
// verification
typedef struct signed_chal {
    byte chal_sig[ECC_SIG_SIZE];
    word32 chal_sig_size;
} signed_chal;

int make_ecc_key(ecc_key *key, WC_RNG *rng);

int load_ap_private_key(ecc_key *key);

int load_comp_private_key(ecc_key *key);

int load_host_public_key(ecc_key *key);

int construct_device_cert_data(cert_data *cert, ecc_key *device_key,
                               word32 dev_id);

int sign_data(const byte *data, word32 data_size, byte *sig, word32 *sig_size,
              ecc_key *key, WC_RNG *rng);

int verify_data_signature(const byte *data, word32 data_size, const byte *sig,
                          word32 sig_size, ecc_key *key);

int create_hello(signed_hello_with_cert *msg, int is_ap, ecc_key *self_dh_key);

int verify_hello(signed_hello_with_cert *msg, byte *shared_key,
                 word32 *shared_key_sz, ecc_key *self_dh_key,
                 word32 sender_device_id, // Component ID or AP tag
                 ecc_key *sender_pubkey);

int simulate_handshake();

#endif
