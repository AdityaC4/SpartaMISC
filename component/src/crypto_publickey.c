#include "crypto_publickey.h"

int make_curve25519_key(curve25519_key *key, WC_RNG *rng)
{
    int ret = wc_curve25519_init(key);
    if (ret == 0)
    {
        ret = wc_curve25519_make_key(rng, ECC_KEY_LEN, key);
    }

    return ret;
}

#ifdef IS_AP
int load_ap_private_key(ed25519_key *key)
{
    int ret = wc_ed25519_init(key);
    if (ret == 0) {
        print_debug("Importing AP private key from der...");

        byte key_der[] = AP_PRIVKEY_DER;
        word32 idx = 0;
        ret =
            wc_Ed25519PrivateKeyDecode(key_der, &idx, key, (word32)sizeof(key_der));
    }

    return ret;
}
#else
int load_ap_private_key(ed25519_key *key) { return -1; }
#endif

#ifdef IS_COMPONENT
int load_comp_private_key(ed25519_key *key)
{
    int ret = wc_ed25519_init(key);
    if (ret == 0)
    {
        print_debug("Importing Component private key from der...");

        byte key_der[] = COMP_PRIVKEY_DER;
        word32 idx = 0;
        ret =
            wc_Ed25519PrivateKeyDecode(key_der, &idx, key, (word32)sizeof(key_der));
    }

    return ret;
}
#else
int load_comp_private_key(ed25519_key *key) { return -1; }
#endif

int load_host_public_key(ed25519_key *key)
{
    int ret = wc_ed25519_init(key);
    if (ret == 0)
    {
        print_debug("Importing host public key from der...");

        byte key_der[] = HOST_PUBKEY_DER;
        word32 idx = 0;
        ret =
            wc_Ed25519PublicKeyDecode(key_der, &idx, key, (word32)sizeof(key_der));
    }

    return ret;
}

// Construct a certificate from a public-only ed25519 key
int construct_device_cert_data(cert_data *cert, ed25519_key *device_key,
                               word32 dev_id)
{
    int ret = 0;

    memcpy(cert->pubkey, device_key->p, ED25519_PUB_KEY_SIZE);

    // ret = wc_ed25519_make_public(device_key, cert->pubkey, ED25519_PUB_KEY_SIZE);

    cert->tag = dev_id;

    return ret;
}

int set_ed25519_pubkey(ed25519_key* key) {
    int ret;

    uint8_t pubKey[ED25519_PUB_KEY_SIZE];
    ret = wc_ed25519_make_public(key, pubKey, ED25519_PUB_KEY_SIZE);
    if (ret == 0)
    {
        ret = wc_ed25519_import_public(pubKey, sizeof(pubKey), key);
    }

    return ret;
}

int sign_data(const byte *data, word32 data_size, byte *sig, word32 *sig_size,
              ed25519_key *key)
{
    byte hash_out[WC_SHA256_DIGEST_SIZE];
    int ret = wc_Sha256Hash(data, data_size, hash_out);

    if (ret != 0)
    {
        print_debug("Error in doing SHA256 hash");
        return -1;
    }

    print_debug("Hash of data: ");
    print_hex_debug(hash_out, WC_SHA256_DIGEST_SIZE);

    // Make the public key from the private key first
    // This is required for signing with Ed25519
    ret = set_ed25519_pubkey(key);

    if (ret != 0) {
        print_debug("Error in making public key from private key!: %d", ret);
        return ret;
    }

    ret = wc_ed25519_sign_msg(hash_out, sizeof(hash_out), sig, sig_size, key);

    return ret;
}

int verify_data_signature(const byte *data, word32 data_size, const byte *sig,
                          word32 sig_size, ed25519_key *key)
{
    print_debug("Hashing data...");

    byte hash_out[WC_SHA256_DIGEST_SIZE];
    int ret = wc_Sha256Hash(data, data_size, hash_out);

    if (ret != 0)
    {
        print_debug("Error in doing SHA256 hash");
        return -1;
    }

    print_debug("Hashed data: ");
    print_hex_debug(hash_out, WC_SHA256_DIGEST_SIZE);

    print_debug("Verifying signature...");

    int verified = -1;
    wc_ed25519_verify_msg(sig, sig_size, hash_out, sizeof(hash_out), &verified,
                          key);

    print_debug("verified and ret: %d and %d", verified, ret);

    if (verified != 1 || ret != 0)
        return -1;
    else
        return 0;
}

/**
 * Creates a hello message containing the device's public key, DH public key,
 * signature of the two and its certificate.
 * This function initializes and sets self_dh_key
 */
int create_hello(signed_hello_with_cert *msg, int is_ap, curve25519_key *self_dh_key)
{
    print_info("In create_hello()");

    print_debug("Size of hello struct: %d", (int)sizeof(hello));

    int ret;

    WC_RNG rng;
    wc_InitRng(&rng);

    memset(msg, 0, sizeof(signed_hello_with_cert));

    ed25519_key self_key;

    if (is_ap)
        ret = load_ap_private_key(&self_key);
    else
        ret = load_comp_private_key(&self_key);

    if (ret != 0)
    {
        print_debug("Error loading device key: %d", ret);
        return -1;
    }

    ret = make_curve25519_key(self_dh_key, &rng);
    if (ret != 0)
    {
        print_debug("Error making DH key: %d", ret);
        return -1;
    }

    ret = wc_ed25519_make_public(&self_key, msg->sh.hi.pubkey, ED25519_PUB_KEY_SIZE);
    if (ret != 0)
    {
        print_debug("Error exporting public key to buffer: %d", ret);
        return -1;
    }
    print_debug("Exported ed25519 public key to buffer: wrote bytes");

    word32 outLen = CURVE25519_PUB_KEY_SIZE;
    ret = wc_curve25519_export_public_ex(self_dh_key, msg->sh.hi.dh_pubkey, &outLen, EC25519_BIG_ENDIAN);
    if (ret != 0)
    {
        print_debug("Error exporting device DH key to buffer: %d", ret);
        return -1;
    }
    print_debug("Exported device DH public key to buffer: wrote %d bytes",
                outLen);

    print_debug("Signing device hello with device public key");

    byte sig_out[ED25519_SIG_SIZE];
    memset(sig_out, 0, ED25519_SIG_SIZE);
    word32 sig_sz = ED25519_SIG_SIZE;

    ret = sign_data((byte *)&(msg->sh.hi), (word32)sizeof(msg->sh.hi), sig_out,
                    &sig_sz, &self_key);
    if (ret != 0)
    {
        print_debug("Error signing hello: %d", ret);
        return -1;
    }

    print_debug("Signature size %d: ", sig_sz);
    print_hex_debug(sig_out, sig_sz);

    // print_debug("Verifying own hello signature: ");

    // ret = verify_data_signature((byte*) &(msg->data.hi), (word32)
    // sizeof(msg->data.hi), sig_out, sig_sz, &ap_key); print_debug("Got result:
    // %d", ret);

    print_debug("Setting device signature in signed_hello");

    memcpy(&(msg->sh.hello_sig), sig_out, sizeof(sig_out));
    msg->sh.hello_sig_size = sig_sz;

    print_debug("Setting host certificate signature in msg");

#ifdef IS_AP
    byte ap_host_cert[] = AP_CERT_SIGNATURE;
#else
    byte ap_host_cert[] = {};
#endif 

#ifdef IS_COMPONENT
    byte comp_host_cert[] = COMP_CERT_SIGNATURE;
#else
    byte comp_host_cert[] = {};
#endif

    if (is_ap)
    {
        memcpy(&(msg->cert_sig), ap_host_cert, sizeof(ap_host_cert));
        msg->cert_sig_size = sizeof(ap_host_cert);
    }
    else
    {
        memcpy(&(msg->cert_sig), comp_host_cert, sizeof(comp_host_cert));
        msg->cert_sig_size = sizeof(comp_host_cert);
    }

    print_debug("Completed construction of hello message: total size %d",
                (int)sizeof(signed_hello_with_cert));
    print_hex_debug((byte *)msg, sizeof(signed_hello_with_cert));

    return ret;
}

/**
 * Verifies a signed_hello_with_cert message from another device.
 * This function initializes and sets a shared key
 * using the sender public DH key from the message packet,
 * and it's own DH key passed as a parameter
 */
int verify_hello(signed_hello_with_cert *msg, byte *shared_key,
                 word32 *shared_key_sz, curve25519_key *self_dh_key,
                 word32 sender_device_id, // Component ID or AP tag
                 ed25519_key *sender_pubkey)
{
    print_info("In verify_hello()");

    int ret;

    WC_RNG rng;
    wc_InitRng(&rng);

    ed25519_key host_pubkey;
    ret = load_host_public_key(&host_pubkey);
    if (ret != 0)
    {
        print_debug("Error loading Host key: %d", ret);
        return -1;
    }

    print_debug("Loading sender public key from msg");

    ret =
        wc_ed25519_import_public_ex((msg->sh).hi.pubkey, ED25519_PUB_KEY_SIZE, sender_pubkey, EC25519_BIG_ENDIAN);
    if (ret != 0)
    {
        print_debug("Error loading sender public key: %d", ret);
        return -1;
    }

    // int check_result = wc_ecc_check_key(sender_pubkey);

    // if (check_result == MP_OKAY)
    // {
    //     print_debug("Key check succeeded");
    // }
    // else
    // {
    //     print_debug("Key check failed");
    // }

    print_debug("Loading sender DH public key from msg");

    curve25519_key sender_dh_pubkey;
    ret = wc_curve25519_init(&sender_dh_pubkey);
    
    ret = wc_curve25519_import_public((msg->sh).hi.dh_pubkey, CURVE25519_PUB_KEY_SIZE, &sender_dh_pubkey);
    if (ret != 0)
    {
        print_debug("Error loading sender DH public key: %d", ret);
        return -1;
    }

    // check_result = wc_ecc_check_key(&sender_dh_pubkey);

    // if (check_result == MP_OKAY)
    // {
    //     print_debug("Key check succeeded");
    // }
    // else
    // {
    //     print_debug("Key check failed");
    // }

    print_debug("Verifying sender Hello signature");

    ret =
        verify_data_signature((byte *)&(msg->sh.hi), (word32)sizeof(msg->sh.hi),
                              (byte *)&(msg->sh.hello_sig),
                              (word32)msg->sh.hello_sig_size, sender_pubkey);
    if (ret != 0)
    {
        print_debug("Failed to verify sender signature of hello");
        return -1;
    }

    print_debug("Creating certificate data from sender key and device id");

    // Load device id

    cert_data cert;
    ret = construct_device_cert_data(&cert, sender_pubkey, sender_device_id);
    if (ret != 0)
    {
        print_debug("Failed to construct certificate");
        return -1;
    }

    print_debug("Verifying sender certificate with host key...");

    ret = verify_data_signature((byte *)&cert, sizeof(cert_data), msg->cert_sig,
                                (word32)msg->cert_sig_size, &host_pubkey);
    if (ret != 0)
    {
        print_debug("Signature verification failed");
        return -1;
    }

    print_debug("Successfully verified sender hello");

    print_debug("Creating shared DH key");

    // self_dh_key->rng = &rng;
    // sender_dh_pubkey.rng = &rng;

    ret = wc_curve25519_shared_secret_ex(self_dh_key, &sender_dh_pubkey, shared_key,
                                         shared_key_sz, EC25519_BIG_ENDIAN);
    if (ret != 0)
    {
        print_debug("Error creating shared key: %d", ret);
        return -1;
    }

    print_debug("Created shared DH key of size %d: ", *shared_key_sz);
    print_hex_debug(shared_key, *shared_key_sz);

    return 0;
}

int simulate_handshake()
{
    print_debug("Size of signed_hello_with_cert: %d",
                (int)sizeof(signed_hello_with_cert));
    // print_debug("Size of signed_hello_with_cert_and_chal: %d",
    // sizeof(signed_hello_with_cert_and_chal));

    WC_RNG rng;
    wc_InitRng(&rng);

    int ret;

    // AP creates hello

    curve25519_key ap_dh_key;
    signed_hello_with_cert msg;

    ret = create_hello(&msg, 1, &ap_dh_key);
    if (ret != 0)
    {
        print_debug("Error creating signed ap hello with cert");
        return -1;
    }

    // --> AP sends this to component

    // Preemptively creating component's hello here first to initialize its DH
    // key
    curve25519_key comp_dh_key;
    print_debug("Creating hello for component");
    signed_hello_with_cert resp;
    ret = create_hello(&resp, 0, &comp_dh_key);

    // Component verifies hello and derives its shared key

    byte comp_shared_key[SHARED_KEY_SIZE];
    word32 comp_shared_key_size = SHARED_KEY_SIZE;

    // This is the AP's public key as parsed by the component from its hello
    // Saved for verifying challenge response signature later
    ed25519_key sender_pubkey_for_comp;
    wc_ed25519_init(&sender_pubkey_for_comp);

    ret = verify_hello(&msg, comp_shared_key, &comp_shared_key_size,
                       &comp_dh_key, AP_TAG, &sender_pubkey_for_comp);
    if (ret != 0)
    {
        print_debug("Failed to verify ap hello");
        return -1;
    }

    // Component signs challenge for its response hello

    ed25519_key comp_key;
    ret = load_comp_private_key(&comp_key);
    if (ret != 0)
    {
        print_debug("Error loading component key: %d", ret);
        return -1;
    }

    print_debug("Component signing AP dh key as challenge");

    byte comp_chal_sig_out[ED25519_SIG_SIZE];
    word32 comp_chal_sig_sz = ED25519_SIG_SIZE;

    ret = sign_data((byte *)&(msg.sh.hi.dh_pubkey), CURVE25519_PUB_KEY_SIZE,
                    comp_chal_sig_out, &comp_chal_sig_sz, &comp_key);
    if (ret != 0)
    {
        print_debug("Error signing AP DH pubkey with component key: %d", ret);
        return -1;
    }

    print_debug("Creating response signature struct");

    signed_chal resp_chal;

    memset(resp_chal.chal_sig, 0, ED25519_SIG_SIZE);
    memcpy(resp_chal.chal_sig, comp_chal_sig_out, comp_chal_sig_sz);
    resp_chal.chal_sig_size = comp_chal_sig_sz;

    // <-- Component sends resp and resp_chal to AP

    // AP verifies component hello along with the challenge signature, derives
    // the shared key

    byte ap_shared_key[SHARED_KEY_SIZE];
    word32 ap_shared_key_size = SHARED_KEY_SIZE;

    // This is the component's pubkey as parsed by the AP from the response
    // Saved for verifying challenge response signature
    ed25519_key sender_pubkey_for_ap;
    wc_ed25519_init(&sender_pubkey_for_ap);

    print_debug("AP verifying component hello: ");

    ret = verify_hello(&resp, ap_shared_key, &ap_shared_key_size, &ap_dh_key,
                       COMPONENT_ID, &sender_pubkey_for_ap);
    if (ret != 0)
    {
        print_debug("Failed to verify component hello");
        return -1;
    }

    print_debug("AP verifying challenge signature from component");
    ret = verify_data_signature((byte *)msg.sh.hi.dh_pubkey, CURVE25519_PUB_KEY_SIZE,
                                resp_chal.chal_sig, resp_chal.chal_sig_size,
                                &sender_pubkey_for_ap);
    if (ret != 0)
    {
        print_debug("Signature verification failed");
        return -1;
    }

    print_debug("AP successfully verified component challenge signature");

    // AP now signs component's DH pubkey as its challenge response
    ed25519_key ap_key;
    ret = load_ap_private_key(&ap_key);
    if (ret != 0)
    {
        print_debug("Error loading AP key: %d", ret);
        return -1;
    }

    print_debug("AP signing Component dh key as challenge");

    byte ap_chal_sig_out[ED25519_SIG_SIZE];
    word32 ap_chal_sig_sz = ED25519_SIG_SIZE;

    ret = sign_data((byte *)&(resp.sh.hi.dh_pubkey), CURVE25519_PUB_KEY_SIZE,
                    ap_chal_sig_out, &ap_chal_sig_sz, &ap_key);
    if (ret != 0)
    {
        print_debug("Error signing component DH pubkey with AP key: %d", ret);
        return -1;
    }

    print_debug("Setting challenge signature in response struct");

    signed_chal sc_msg;

    memset(sc_msg.chal_sig, 0, ED25519_SIG_SIZE);
    memcpy(sc_msg.chal_sig, ap_chal_sig_out, ap_chal_sig_sz);
    sc_msg.chal_sig_size = ap_chal_sig_sz;

    // --> AP sends sc_msg to component

    print_debug("Component verifying signed challenge from AP");

    ret = verify_data_signature((byte *)&(resp.sh.hi.dh_pubkey), CURVE25519_PUB_KEY_SIZE,
                                sc_msg.chal_sig, sc_msg.chal_sig_size,
                                &sender_pubkey_for_comp);
    if (ret != 0)
    {
        print_debug("Signature verification failed");
        return -1;
    }

    print_debug("Component successfully verified AP challenge signature");

    print_debug("HANDSHAKE COMPLETE :))))");

    return 1;
}