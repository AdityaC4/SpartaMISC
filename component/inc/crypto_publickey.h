#ifndef ECTF_CRYPTO_TEST_H
#define ECTF_CRYPTO_TEST_H

#include "ectf_params.h"
#include "ectf_keys.h"
#include "host_messaging.h"

#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/integer.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/curve25519.h"

#define ECC_CURVE ECC_X25519
#define ECC_KEY_LEN 32

#define PUBKEY_BUF_LEN ECC_BUFSIZE
#define PUBKEY_LEN ECC_MAXSIZE + 1

#define POINT_SIZE 32
#define ECC_SIG_SIZE ED25519_SIG_SIZE // was 72

#define SHARED_KEY_SIZE 32

#define AP_TAG 0xffffffff

#define IS_COMPONENT 1

// All of these should be smaller than MAX_I2C_MESSAGE_LEN-1

/**
* Certificate data for a device
* Includes the device's public key and its identifier
*/
typedef struct cert_data
{
    byte pubkey[ED25519_PUB_KEY_SIZE];
    word32 tag;
} cert_data;

/**
* The raw data portion of the initial hello messages
* Contain the device public key and the generated ECDH public key
*/
typedef struct hello
{
    byte pubkey[ED25519_PUB_KEY_SIZE];
    byte dh_pubkey[CURVE25519_PUB_KEY_SIZE];
} hello;

/**
* The signed hello, containing the hello along with an Ed25519 signature
*/
typedef struct signed_hello
{
    hello hi;
    byte hello_sig[ED25519_SIG_SIZE];
    word32 hello_sig_size;
} signed_hello;

/**
* The signed hello with the certificate for the device
*/
typedef struct signed_hello_with_cert
{
    signed_hello sh;

    byte cert_sig[ED25519_SIG_SIZE];
    word32 cert_sig_size;
} signed_hello_with_cert;

// Sent back by the AP to the Component as AP's challenge-response to finish the verification
typedef struct signed_chal
{
    byte chal_sig[ED25519_SIG_SIZE];
    word32 chal_sig_size;
} signed_chal;

/**
* Makes a Curve25519 key for ECDH
* 
* @param key The curve25519_key
* @param rng Pointer to the WC_RNG
* @return status
*/
int make_ecc_key(curve25519_key *key, WC_RNG *rng);

/**
* Loads the AP's private key into a key object
* 
* @param key The ed25519 key
* @return status
*/
int load_ap_private_key(ed25519_key *key);

/**
* Loads the Component's private key into a key object
* 
* @param key The ed25519 key
* @return status
*/
int load_comp_private_key(ed25519_key *key);

/**
* Loads the Host's public key into a key object
* 
* @param key The ed25519 key
* @return status
*/
int load_host_public_key(ed25519_key *key);

/**
* Creates certificate data given a device key and the device id
* 
* @param device_key The ed25519 key to be used in the certifcate
* @param dev_id The device id (COMPONENT_ID or AP_TAG)
* @return status
*/
int construct_device_cert_data(cert_data *cert, ed25519_key *device_key,
                               word32 dev_id);

/**
* Signs the given data using the provided key
* 
* @param data Pointer to the buffer of data
* @param data_size Size of the data buffer
* @param sig Pointer to the signature buffer
* @param sig_size Pointer to the signature size
* @param key Pointer to the ed25519 key used to sign
* @return status
*/
int sign_data(const byte *data, word32 data_size, byte *sig, word32 *sig_size,
              ed25519_key *key);

/**
* Verifies the signature of some data using the provided public key
* 
* @param data Pointer to the buffer of data
* @param data_size Size of the data buffer
* @param sig Pointer to the signature buffer
* @param sig_size The signature size
* @param key Pointer to the ed25519 public key used to sign the data
* @return status
*/
int verify_data_signature(const byte *data, word32 data_size, const byte *sig,
                          word32 sig_size, ed25519_key *key);

/**
* Creates and initializes a signed_hello_with_cert object
* Also initializes the ECDH key for the device
* 
* @param msg Pointer to the signed_hello_with_cert to initialize
* @param is_ap Whether the hello is being created by an AP or Component
* @param key Pointer to the curve25519 key used for shared secret derivation
* @return status
*/
int create_hello(signed_hello_with_cert *msg, int is_ap, curve25519_key *self_dh_key);

/**
* Verifies a signed_hello_with_cert and derives the ECDH key
* 
* @param msg Pointer to the signed_hello_with_cert message received
* @param shared_key Pointer to the buffer to store the shared key in
* @param shared_key_sz Pointer to the shared key size
* @param self_dh_key Pointer to the device's own public key used for ECDH
* @param sender_device_id The device ID of the device to verify
* @param sender_pubkey Pointer to the public key for the sender
* @return status
*/
int verify_hello(signed_hello_with_cert *msg, byte *shared_key,
                 word32 *shared_key_sz, curve25519_key *self_dh_key,
                 word32 sender_device_id, // Component ID or AP tag
                 ed25519_key *sender_pubkey);

/**
* Simulates the handshake process between an AP and Component
*
* @return status
*/
int simulate_handshake();

#endif
