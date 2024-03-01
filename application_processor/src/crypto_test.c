#include "crypto_test.h"

int make_ecc_key(ecc_key *key, WC_RNG *rng) {
    int ret = wc_ecc_init(key);
    if (ret == 0) {
        ret = wc_ecc_make_key_ex(rng, ECC_KEY_LEN, key, ECC_CURVE);
    }

    return ret;
}

int load_ap_private_key(ecc_key *key) {
    int ret = wc_ecc_init(key);
    if (ret == 0) {
        print_debug("Importing AP private key from der...");

        byte key_der[] = AP_PRIVKEY_DER;
        word32 idx = 0;
        ret =
            wc_EccPrivateKeyDecode(key_der, &idx, key, (word32)sizeof(key_der));
    }

    return ret;
}

int load_comp_private_key(ecc_key *key) {
    int ret = wc_ecc_init(key);
    if (ret == 0) {
        print_debug("Importing Component private key from der...");

        byte key_der[] = COMP_PRIVKEY_DER;
        word32 idx = 0;
        ret =
            wc_EccPrivateKeyDecode(key_der, &idx, key, (word32)sizeof(key_der));
    }

    return ret;
}

int load_host_public_key(ecc_key *key) {
    int ret = wc_ecc_init(key);
    if (ret == 0) {
        print_debug("Importing host public key from der...");

        byte key_der[] = HOST_PUBKEY_DER;
        word32 idx = 0;
        ret =
            wc_EccPublicKeyDecode(key_der, &idx, key, (word32)sizeof(key_der));
    }

    return ret;
}

int construct_device_cert_data(cert_data *cert, ecc_key *device_key,
                               word32 dev_id) {
    int ret = 0;

    // mp_to_unsigned_bin stores point in buffer in big-endian format

    byte point_x[POINT_SIZE];
    ret = mp_to_unsigned_bin((mp_int *)&((device_key->pubkey).x), point_x);
    if (ret != 0)
        return ret;

    byte point_y[POINT_SIZE];
    ret = mp_to_unsigned_bin((mp_int *)&((device_key->pubkey).y), point_y);
    if (ret != 0)
        return ret;

    // memcpy(cert->pubkey_x, (ap_key->pubkey).x[0].dp, POINT_SIZE);
    // memcpy(cert->pubkey_y, (ap_key->pubkey).y[0].dp, POINT_SIZE);

    memcpy(cert->pubkey_x, point_x, POINT_SIZE);
    memcpy(cert->pubkey_y, point_y, POINT_SIZE);

    cert->tag = dev_id;

    return ret;
}

int sign_data(const byte *data, word32 data_size, byte *sig, word32 *sig_size,
              ecc_key *key, WC_RNG *rng) {
    byte hash_out[WC_SHA256_DIGEST_SIZE];
    int ret = wc_Sha256Hash(data, data_size, hash_out);

    if (ret != 0) {
        print_debug("Error in doing SHA256 hash");
        return -1;
    }

    print_debug("Hash of data: ");
    print_hex_debug(hash_out, WC_SHA256_DIGEST_SIZE);

    ret = wc_ecc_sign_hash(hash_out, WC_SHA256_DIGEST_SIZE, sig, sig_size, rng,
                           key);

    return ret;
}

int verify_data_signature(const byte *data, word32 data_size, const byte *sig,
                          word32 sig_size, ecc_key *key) {
    print_debug("Hashing data...");

    byte hash_out[WC_SHA256_DIGEST_SIZE];
    int ret = wc_Sha256Hash(data, data_size, hash_out);

    if (ret != 0) {
        print_debug("Error in doing SHA256 hash");
        return -1;
    }

    print_debug("Hashed data: ");
    print_hex_debug(hash_out, WC_SHA256_DIGEST_SIZE);

    print_debug("Verifying signature...");

    int stat = -1;
    ret = wc_ecc_verify_hash(sig, sig_size, hash_out, WC_SHA256_DIGEST_SIZE,
                             &stat, key);

    print_debug("Stat and ret: %d and %d", stat, ret);

    if (stat != 1 || ret != 0)
        return -1;
    else
        return 0;
}

/**
 * Creates a hello message containing the device's public key, DH public key,
 * signature of the two and its certificate.
 * This function initializes and sets self_dh_key
 */
int create_hello(signed_hello_with_cert *msg, int is_ap, ecc_key *self_dh_key) {
    print_info("In create_hello()");

    print_debug("Size of hello struct: %d", (int)sizeof(hello));

    int ret;

    WC_RNG rng;
    wc_InitRng(&rng);

    memset(msg, 0, sizeof(signed_hello_with_cert));

    ecc_key self_key;

    if (is_ap)
        ret = load_ap_private_key(&self_key);
    else
        ret = load_comp_private_key(&self_key);

    if (ret != 0) {
        print_debug("Error loading device key: %d", ret);
        return -1;
    }

    ret = make_ecc_key(self_dh_key, &rng);
    if (ret != 0) {
        print_debug("Error making DH key: %d", ret);
        return -1;
    }

    word32 outLen = COMPR_KEY_BUFSIZE;
    ret = wc_ecc_export_x963_ex(&self_key, msg->sh.hi.pubkey, &outLen, 1);
    if (ret != 0) {
        print_debug("Error exporting key to buffer: %d", ret);
        return -1;
    }
    print_debug("Exported device public key to buffer: wrote %d bytes", outLen);

    outLen = COMPR_KEY_BUFSIZE;
    ret = wc_ecc_export_x963_ex(self_dh_key, msg->sh.hi.dh_pubkey, &outLen, 1);
    if (ret != 0) {
        print_debug("Error exporting device DH key to buffer: %d", ret);
        return -1;
    }
    print_debug("Exported device DH public key to buffer: wrote %d bytes",
                outLen);

    print_debug("Signing device hello with device public key");

    byte sig_out[ECC_SIG_SIZE];
    memset(sig_out, 0, ECC_SIG_SIZE);
    word32 sig_sz = ECC_SIG_SIZE;

    ret = sign_data((byte *)&(msg->sh.hi), (word32)sizeof(msg->sh.hi), sig_out,
                    &sig_sz, &self_key, &rng);
    if (ret != 0) {
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

    byte ap_host_cert[] = AP_CERT_SIGNATURE;
    byte comp_host_cert[] = COMP_CERT_SIGNATURE;

    if (is_ap) {
        memcpy(&(msg->cert_sig), ap_host_cert, sizeof(ap_host_cert));
        msg->cert_sig_size = sizeof(ap_host_cert);
    } else {
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
                 word32 *shared_key_sz, ecc_key *self_dh_key,
                 word32 sender_device_id, // Component ID or AP tag
                 ecc_key *sender_pubkey) {
    print_info("In verify_hello()");

    int ret;

    WC_RNG rng;
    wc_InitRng(&rng);

    ecc_key host_pubkey;
    ret = load_host_public_key(&host_pubkey);
    if (ret != 0) {
        print_debug("Error loading Host key: %d", ret);
        return -1;
    }

    print_debug("Loading sender public key from msg");

    ret =
        wc_ecc_import_x963((msg->sh).hi.pubkey, COMPR_KEY_SIZE, sender_pubkey);
    if (ret != 0) {
        print_debug("Error sender public key: %d", ret);
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

    ecc_key sender_dh_pubkey;
    ret = wc_ecc_import_x963((msg->sh).hi.dh_pubkey, COMPR_KEY_SIZE,
                             &sender_dh_pubkey);
    if (ret != 0) {
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
    if (ret != 0) {
        print_debug("Failed to verify sender signature of hello");
        return -1;
    }

    print_debug("Creating certificate data from sender key and device id");

    // Load device id

    cert_data cert;
    ret = construct_device_cert_data(&cert, sender_pubkey, sender_device_id);
    if (ret != 0) {
        print_debug("Failed to construct certificate");
        return -1;
    }

    print_debug("Verifying sender certificate with host key...");

    ret = verify_data_signature((byte *)&cert, CERT_DATA_SIZE, msg->cert_sig,
                                (word32)msg->cert_sig_size, &host_pubkey);
    if (ret != 0) {
        print_debug("Signature verification failed");
        return -1;
    }

    print_debug("Successfully verified sender hello");

    print_debug("Creating shared DH key");

    // comp_dh_key->rng = &rng;
    // ap_dh_pubkey.rng = &rng;

    ret = wc_ecc_shared_secret(self_dh_key, &sender_dh_pubkey, shared_key,
                               shared_key_sz);
    if (ret != 0) {
        print_debug("Error creating shared key: %d", ret);
        return -1;
    }

    print_debug("Created shared DH key of size %d: ", *shared_key_sz);
    print_hex_debug(shared_key, *shared_key_sz);

    return 0;
}

int simulate_handshake() {
    print_debug("Size of signed_hello_with_cert: %d",
                (int)sizeof(signed_hello_with_cert));
    // print_debug("Size of signed_hello_with_cert_and_chal: %d",
    // sizeof(signed_hello_with_cert_and_chal));

    WC_RNG rng;
    wc_InitRng(&rng);

    int ret;

    // AP creates hello

    ecc_key ap_dh_key;
    signed_hello_with_cert msg;

    ret = create_hello(&msg, 1, &ap_dh_key);
    if (ret != 0) {
        print_debug("Error creating signed ap hello with cert");
        return -1;
    }

    // --> AP sends this to component

    // Preemptively creating component's hello here first to initialize its DH
    // key
    ecc_key comp_dh_key;
    print_debug("Creating hello for component");
    signed_hello_with_cert resp;
    ret = create_hello(&resp, 0, &comp_dh_key);

    // Component verifies hello and derives its shared key

    byte comp_shared_key[SHARED_KEY_SIZE];
    word32 comp_shared_key_size = SHARED_KEY_SIZE;

    // This is the AP's public key as parsed by the component from its hello
    // Saved for verifying challenge response signature later
    ecc_key sender_pubkey_for_comp;
    wc_ecc_init(&sender_pubkey_for_comp);

    ret = verify_hello(&msg, comp_shared_key, &comp_shared_key_size,
                       &comp_dh_key, AP_TAG, &sender_pubkey_for_comp);
    if (ret != 0) {
        print_debug("Failed to verify ap hello");
        return -1;
    }

    // Component signs challenge for its response hello

    ecc_key comp_key;
    ret = load_comp_private_key(&comp_key);
    if (ret != 0) {
        print_debug("Error loading component key: %d", ret);
        return -1;
    }

    print_debug("Component signing AP dh key as challenge");

    byte comp_chal_sig_out[ECC_SIG_SIZE];
    word32 comp_chal_sig_sz = ECC_SIG_SIZE;

    ret = sign_data((byte *)&(msg.sh.hi.dh_pubkey), COMPR_KEY_SIZE,
                    comp_chal_sig_out, &comp_chal_sig_sz, &comp_key, &rng);
    if (ret != 0) {
        print_debug("Error signing AP DH pubkey with component key: %d", ret);
        return -1;
    }

    print_debug("Creating response signature struct");

    signed_chal resp_chal;

    memset(resp_chal.chal_sig, 0, ECC_SIG_SIZE);
    memcpy(resp_chal.chal_sig, comp_chal_sig_out, comp_chal_sig_sz);
    resp_chal.chal_sig_size = comp_chal_sig_sz;

    // <-- Component sends resp and resp_chal to AP

    // AP verifies component hello along with the challenge signature, derives
    // the shared key

    byte ap_shared_key[SHARED_KEY_SIZE];
    word32 ap_shared_key_size = SHARED_KEY_SIZE;

    // This is the component's pubkey as parsed by the AP from the response
    // Saved for verifying challenge response signature
    ecc_key sender_pubkey_for_ap;
    wc_ecc_init(&sender_pubkey_for_ap);

    print_debug("AP verifying component hello: ");

    ret = verify_hello(&resp, ap_shared_key, &ap_shared_key_size, &ap_dh_key,
                       COMPONENT_ID, &sender_pubkey_for_ap);
    if (ret != 0) {
        print_debug("Failed to verify component hello");
        return -1;
    }

    print_debug("AP verifying challenge signature from component");
    ret = verify_data_signature((byte *)msg.sh.hi.dh_pubkey, COMPR_KEY_SIZE,
                                resp_chal.chal_sig, resp_chal.chal_sig_size,
                                &sender_pubkey_for_ap);
    if (ret != 0) {
        print_debug("Signature verification failed");
        return -1;
    }

    print_debug("AP successfully verified component challenge signature");

    // AP now signs component's DH pubkey as its challenge response
    ecc_key ap_key;
    ret = load_ap_private_key(&ap_key);
    if (ret != 0) {
        print_debug("Error loading AP key: %d", ret);
        return -1;
    }

    print_debug("AP signing Component dh key as challenge");

    byte ap_chal_sig_out[ECC_SIG_SIZE];
    word32 ap_chal_sig_sz = ECC_SIG_SIZE;

    ret = sign_data((byte *)&(resp.sh.hi.dh_pubkey), COMPR_KEY_SIZE,
                    ap_chal_sig_out, &ap_chal_sig_sz, &ap_key, &rng);
    if (ret != 0) {
        print_debug("Error signing component DH pubkey with AP key: %d", ret);
        return -1;
    }

    print_debug("Setting challenge signature in response struct");

    signed_chal sc_msg;

    memset(sc_msg.chal_sig, 0, ECC_SIG_SIZE);
    memcpy(sc_msg.chal_sig, ap_chal_sig_out, ap_chal_sig_sz);
    sc_msg.chal_sig_size = ap_chal_sig_sz;

    // --> AP sends sc_msg to component

    print_debug("Component verifying signed challenge from AP");

    ret = verify_data_signature((byte *)&(resp.sh.hi.dh_pubkey), COMPR_KEY_SIZE,
                                sc_msg.chal_sig, sc_msg.chal_sig_size,
                                &sender_pubkey_for_comp);
    if (ret != 0) {
        print_debug("Signature verification failed");
        return -1;
    }

    print_debug("Component successfully verified AP challenge signature");

    print_debug("HANDSHAKE COMPLETE :))))");

    return 1;
}

// int verify_self_cert() {
// 	print_info("In verify_self_cert");

// 	WC_RNG mRng;
// 	wc_InitRng(&mRng);

// 	int ret; 

// 	ecc_key host_pubkey;
// 	ret = load_host_public_key(&host_pubkey);
// 	if (ret != 0) {
// 		print_debug("Error loading host public key: %d", ret);
// 		return -1;
// 	}

// 	ecc_key ap_key;
// 	ret = load_ap_private_key(&ap_key);
// 	if (ret != 0) {
// 		print_debug("Error loading AP key: %d", ret);
// 		return -1;
// 	}

// 	print_debug("Dumping AP key x and y points: ");
// 	print_hex_debug((byte*) ap_key.pubkey.x[0].dp, POINT_SIZE);
// 	print_hex_debug((byte*) ap_key.pubkey.y[0].dp, POINT_SIZE);

// 	print_debug("Creating certificate data from AP key");

// 	cert_data cert;
// 	construct_ap_cert_data(&cert, &ap_key);

// 	// sanity check
// 	print_debug("Sizeof cert_data is %d and CERT_DATA_SIZE is %d", (int) sizeof(cert_data), CERT_DATA_SIZE);

// 	print_debug("Certificate data:");
// 	print_hex_debug((byte *) &cert, CERT_DATA_SIZE);

// 	byte cert_sig[] = CERT_SIGNATURE;

// 	ret = verify_data_signature((byte*) &cert, CERT_DATA_SIZE, cert_sig, (word32) sizeof(cert_sig), &host_pubkey);

// 	if (ret != 0) {
//         print_debug("Signature verification failed");
//         return -1;
//     }
//     else {
//     	print_debug("Signature verified successfully! ");
//     }

//     return 1;
// }

// int create_keypair() {
// 	print_info("In create_keypair()");

// 	// verify_self_cert();

// 	// simulate_handshake();

// 	WC_RNG mRng;
// 	wc_InitRng(&mRng);

// 	int ret; 
// 	ecc_key key; 

// 	ret = wc_ecc_init(&key);

//     if (ret == 0) {
//         // ret = wc_ecc_make_key_ex(&mRng, 32, &key, ECC_CURVE);

//         print_debug("Importing key from der...");

//         byte privkeyder[] = AP_PRIVKEY_DER;
//         word32 idx = 0;
//         ret = wc_EccPrivateKeyDecode(privkeyder, &idx, &key, (word32) sizeof(privkeyder));
//     }

//     if (ret != 0) {
//         print_debug("ecc make key failed %d\n", ret);
//         return -1;
//     }

//     print_debug("Key initialized!");

//     int check_result = wc_ecc_check_key(&key);

// 	if (check_result == MP_OKAY)
// 	{
// 	    print_debug("Key check succeeded");
// 	}
// 	else
// 	{
// 	    print_debug("Key check failed");
// 	}

// 	// HASH DATA
// 	char data[] = "Hello, this is a message for testing wolfSSL. The documentation is good but often confusing. I still don't know if wolfCrypt can work without dynamic memory or not.";

// 	print_debug("Running SHA256 hash on data...");
// 	byte hash_out[WC_SHA256_DIGEST_SIZE];
// 	ret = wc_Sha256Hash((byte*) data, sizeof(data), hash_out);

// 	if (ret != 0) {
// 		print_debug("Error in doing SHA256 hash");
// 		return -1;
// 	}

// 	print_debug("Hashed data: ");
// 	print_hex_debug(hash_out, WC_SHA256_DIGEST_SIZE);

// 	// SIGN HASH
// 	byte sig_out[ECC_MAX_SIG_SIZE]; // An ECC signature is twice the length of the private key
// 	memset(sig_out, 0, ECC_MAX_SIG_SIZE);
// 	word32 sigSz = ECC_SIG_SIZE;

// 	print_debug("Signing hash with ECC key... ");
// 	ret = wc_ecc_sign_hash(hash_out, WC_SHA256_DIGEST_SIZE, sig_out, &sigSz, &mRng, &key);
// 	if (ret != 0) {
// 		print_debug("Error signing hash.");
// 		return -1;
// 	}
// 	print_debug("Signed hash with signature length %d:", sigSz);
// 	print_hex_debug(sig_out, sigSz);

// 	// EXPORT PUBLIC KEY
// 	print_debug("Exporting public key to x963...");

// 	byte pubkey_buf[PUBKEY_BUF_LEN];
// 	word32 pubkey_buf_size = PUBKEY_BUF_LEN;
// 	memset(pubkey_buf, 0, PUBKEY_BUF_LEN);

// 	ret = wc_ecc_export_x963(&key, pubkey_buf, &pubkey_buf_size);
// 	if (ret != 0) {
// 		print_debug("ECC public key x963 export failed! %d\n", ret);
// 		return -1;
// 	}
// 	print_debug("Exported public key to a buffer as x963 of size %d: ", pubkey_buf_size);
// 	print_hex_debug(pubkey_buf, PUBKEY_BUF_LEN);

// 	// IMPORT INTO NEW KEY
// 	print_debug("Importing public key into new object...");

// 	ecc_key key2; 

// 	ret = wc_ecc_init(&key2);
// 	if (ret != 0) {
// 		print_debug("Could not initialize new key");
// 		return -1;
// 	}
	
// 	ret = wc_ecc_import_x963_ex(pubkey_buf, pubkey_buf_size, &key2, ECC_CURVE);

//     if (ret != 0) {
//         print_debug("Ecc import x963 failed %d\n", ret);
//         return -1;
//     }

//     print_debug("Succesfully imported public key!");

//     // VERIFY HASH
//     print_debug("Verifying signature with imported public key...");

//     int stat = -1;

// 	// TEST
// 	// sigSz = ECC_SIG_SIZE;

//     ret = wc_ecc_verify_hash(sig_out, sigSz, hash_out, WC_SHA256_DIGEST_SIZE, &stat, &key2);

//     if (ret != 0) {
//         print_debug("Signature verification returned error %d\n", ret);
//         return -1;
//     }
//     if (stat != 1) {
//         print_debug("Signature verification rejected %d\n", stat);
//         // return -1;
//     } else {
//     	print_debug("Signature verified successfully! ");
//     }

//     // dertest();

// 	// FREE STUFF
// 	// print_debug("'Freeing' WC_RNG and ECC key... (?)");
// 	// wc_ecc_key_free(&key);
// 	// ret = wc_FreeRng(&mRng);
// 	// print_debug("WC_RNG and ECC Key 'freed' with ret %d.", ret);


// 	return 0;

// }