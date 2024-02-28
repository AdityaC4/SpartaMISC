#include "crypto_test.h"
#include "host_messaging.h"
#include "ectf_keys.h"

#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/integer.h"

#define ECC_CURVE			ECC_SECP256R1
#define ECC_KEY_LEN			32

#define COMP_KEY_SIZE		33
#define COMP_KEY_BUFSIZE	36 	// To avoid struct padding issues, just in case

#define PUBKEY_BUF_LEN		ECC_BUFSIZE
#define PUBKEY_LEN 			ECC_MAXSIZE+1

#define POINT_SIZE			32
#define CERT_DATA_SIZE		2 * POINT_SIZE + 4
#define ECC_SIG_SIZE 		72
// #define MAX_CERT_SIZE       4096

typedef struct cert_data {
	byte pubkey_x[32];
	byte pubkey_y[32];
	word32 tag;
} cert_data;

typedef struct ap_hello {
	// Compressed ANSI X9.63 keys
	byte ap_pubkey[COMP_KEY_BUFSIZE];
	byte ap_dh_pubkey[COMP_KEY_BUFSIZE];
} ap_hello;

typedef struct signed_ap_hello {
	ap_hello hi;
	byte hello_sig[ECC_SIG_SIZE];
} signed_ap_hello;

typedef struct signed_ap_hello_with_cert {
	signed_ap_hello data;
	byte cert_sig[ECC_SIG_SIZE];
} signed_ap_hello_with_cert;

int make_ecc_key(ecc_key* key, WC_RNG* rng) {
	int ret = wc_ecc_init(key);
	if (ret == 0) {
		ret = wc_ecc_make_key_ex(rng, ECC_KEY_LEN, key, ECC_CURVE);
	}

	return ret;
}

int load_ap_private_key(ecc_key* key) {
	int ret = wc_ecc_init(key);
	if (ret == 0) {
		print_debug("Importing AP private key from der...");

        byte key_der[] = AP_PRIVKEY_DER;
        word32 idx = 0;
        ret = wc_EccPrivateKeyDecode(key_der, &idx, key, (word32) sizeof(key_der));
	}

	return ret;
}

int load_host_public_key(ecc_key* key) {
	int ret = wc_ecc_init(key);
	if (ret == 0) {
		print_debug("Importing host public key from der...");

        byte key_der[] = HOST_PUBKEY_DER;
        word32 idx = 0;
        ret = wc_EccPublicKeyDecode(key_der, &idx, key, (word32) sizeof(key_der));
	}

	return ret;
}

int construct_ap_cert_data(cert_data* cert, ecc_key* ap_key) {
	int ret = 0;

	// mp_to_unsigned_bin stores point in buffer in big-endian format

	byte point_x[POINT_SIZE];
	ret = mp_to_unsigned_bin((mp_int *) &((ap_key->pubkey).x), point_x);
	if (ret != 0) return ret;

	byte point_y[POINT_SIZE];
	ret = mp_to_unsigned_bin((mp_int *) &((ap_key->pubkey).y), point_y);
	if (ret != 0) return ret;

	// memcpy(cert->pubkey_x, (ap_key->pubkey).x[0].dp, POINT_SIZE);
	// memcpy(cert->pubkey_y, (ap_key->pubkey).y[0].dp, POINT_SIZE);

	memcpy(cert->pubkey_x, point_x, POINT_SIZE);
	memcpy(cert->pubkey_y, point_y, POINT_SIZE);

	cert->tag = (word32) 0xffffffff;

	return ret;
}

int verify_data_signature(byte* data, word32 data_size, byte* sig, word32 sig_size, ecc_key* key) {
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
	ret = wc_ecc_verify_hash(sig, sig_size, hash_out, WC_SHA256_DIGEST_SIZE, &stat, key);

	if (stat != 1 || ret != 0) return -1;
	else return 0;
}

int sign_data(byte* data, word32 data_size, byte* sig, word32* sig_size, ecc_key* key, WC_RNG* rng) {
	byte hash_out[WC_SHA256_DIGEST_SIZE];
	int ret = wc_Sha256Hash(data, data_size, hash_out);

	if (ret != 0) {
		print_debug("Error in doing SHA256 hash");
		return -1;
	}

	ret = wc_ecc_sign_hash(hash_out, WC_SHA256_DIGEST_SIZE, sig, sig_size, rng, key);

	return ret;
}

int create_hello() {
	print_info("In create_hello()");

	print_debug("Size of ap_hello struct: %d", sizeof(ap_hello));

	int ret;

	WC_RNG rng;
	wc_InitRng(&rng);

	signed_ap_hello_with_cert msg;
	memset(&msg, 0, sizeof(msg));

	ecc_key ap_key;
	ret = load_ap_private_key(&ap_key);
	if (ret != 0) {
		print_debug("Error loading AP key: %d", ret);
		return -1;
	}

	ecc_key ap_dh_key;
	ret = make_ecc_key(&ap_dh_key, &rng);
	if (ret != 0) {
		print_debug("Error making AP DH key: %d", ret);
		return -1;
	}

	word32 outLen = COMP_KEY_BUFSIZE;
	ret = wc_ecc_export_x963_ex(&ap_key, msg.data.hi.ap_pubkey, &outLen, 1);
	if (ret != 0) {
		print_debug("Error exporting AP key to buffer: %d", ret);
		return -1;
	}
	print_debug("Exported AP public key to buffer: wrote %d bytes", outLen);

	outLen = COMP_KEY_BUFSIZE;
	ret = wc_ecc_export_x963_ex(&ap_dh_key, msg.data.hi.ap_dh_pubkey, &outLen, 1);
	if (ret != 0) {
		print_debug("Error exporting AP DH key to buffer: %d", ret);
		return -1;
	}
	print_debug("Exported AP DH public key to buffer: wrote %d bytes", outLen);

	print_debug("Signing ap hello with ap public key");

	byte sig_out[ECC_SIG_SIZE];
	memset(sig_out, 0, ECC_SIG_SIZE);
	word32 sig_sz = ECC_SIG_SIZE;

	ret = sign_data((byte*) &msg.data.hi, (word32) sizeof(msg.data.hi), sig_out, &sig_sz, &ap_key, &rng);
	if (ret != 0) {
		print_debug("Error signing ap hello: %d", ret);
		return -1;
	}

	print_debug("Setting AP signature in signed_ap_hello");

	memcpy(&(msg.data.hello_sig), sig_out, sizeof(sig_out));

	print_debug("Setting host certificate signature in msg");

	byte host_cert[] = CERT_SIGNATURE;
	memcpy(&(msg.cert_sig), host_cert, sizeof(host_cert));

	print_debug("Completed construction of AP hello message: total size %d", sizeof(msg));
	print_hex_debug((byte *) &msg, sizeof(msg));

	print_debug("Freeing resources");
	wc_ecc_key_free(&ap_key);
	wc_ecc_key_free(&ap_dh_key);
	ret = wc_FreeRng(&rng);

	return ret;
}

int verify_self_cert() {
	print_info("In verify_self_cert");

	WC_RNG mRng;
	wc_InitRng(&mRng);

	int ret; 

	ecc_key host_pubkey;
	ret = load_host_public_key(&host_pubkey);
	if (ret != 0) {
		print_debug("Error loading host public key: %d", ret);
		return -1;
	}

	ecc_key ap_key;
	ret = load_ap_private_key(&ap_key);
	if (ret != 0) {
		print_debug("Error loading AP key: %d", ret);
		return -1;
	}

	print_debug("Dumping AP key x and y points: ");
	print_hex_debug((byte*) ap_key.pubkey.x[0].dp, POINT_SIZE);
	print_hex_debug((byte*) ap_key.pubkey.y[0].dp, POINT_SIZE);

	print_debug("Creating certificate data from AP key");

	cert_data cert;
	construct_ap_cert_data(&cert, &ap_key);

	// sanity check
	print_debug("Sizeof cert_data is %d and CERT_DATA_SIZE is %d", sizeof(cert_data), CERT_DATA_SIZE);

	print_debug("Certificate data:");
	print_hex_debug((byte *) &cert, CERT_DATA_SIZE);

	byte cert_sig[] = CERT_SIGNATURE;

	ret = verify_data_signature((byte*) &cert, CERT_DATA_SIZE, cert_sig, (word32) sizeof(cert_sig), &host_pubkey);

	if (ret != 0) {
        print_debug("Signature verification failed");
        return -1;
    }
    else {
    	print_debug("Signature verified successfully! ");
    }

    return 1;
}

int create_keypair() {
	print_info("In create_keypair()");

	verify_self_cert();

	create_hello();

	WC_RNG mRng;
	wc_InitRng(&mRng);

	int ret; 
	ecc_key key; 

	ret = wc_ecc_init(&key);

    if (ret == 0) {
        // ret = wc_ecc_make_key_ex(&mRng, 32, &key, ECC_CURVE);

        print_debug("Importing key from der...");

        byte privkeyder[] = AP_PRIVKEY_DER;
        word32 idx = 0;
        ret = wc_EccPrivateKeyDecode(privkeyder, &idx, &key, (word32) sizeof(privkeyder));
    }

    if (ret != 0) {
        print_debug("ecc make key failed %d\n", ret);
        return -1;
    }

    print_debug("Key initialized!");

    int check_result = wc_ecc_check_key(&key);

	if (check_result == MP_OKAY)
	{
	    print_debug("Key check succeeded");
	}
	else
	{
	    print_debug("Key check failed");
	}

	// HASH DATA
	char data[] = "Hello, this is a message for testing wolfSSL. The documentation is good but often confusing. I still don't know if wolfCrypt can work without dynamic memory or not.";

	print_debug("Running SHA256 hash on data...");
	byte hash_out[WC_SHA256_DIGEST_SIZE];
	ret = wc_Sha256Hash((byte*) data, sizeof(data), hash_out);

	if (ret != 0) {
		print_debug("Error in doing SHA256 hash");
		return -1;
	}

	print_debug("Hashed data: ");
	print_hex_debug(hash_out, WC_SHA256_DIGEST_SIZE);

	// SIGN HASH
	byte sig_out[ECC_MAX_SIG_SIZE]; // An ECC signature is twice the length of the private key
	memset(sig_out, 0, ECC_MAX_SIG_SIZE);
	word32 sigSz = ECC_SIG_SIZE;

	print_debug("Signing hash with ECC key... ");
	ret = wc_ecc_sign_hash(hash_out, WC_SHA256_DIGEST_SIZE, sig_out, &sigSz, &mRng, &key);
	if (ret != 0) {
		print_debug("Error signing hash.");
		return -1;
	}
	print_debug("Signed hash with signature length %d:", sigSz);
	print_hex_debug(sig_out, sigSz);

	// EXPORT PUBLIC KEY
	print_debug("Exporting public key to x963...");

	byte pubkey_buf[PUBKEY_BUF_LEN];
	word32 pubkey_buf_size = PUBKEY_BUF_LEN;
	memset(pubkey_buf, 0, PUBKEY_BUF_LEN);

	ret = wc_ecc_export_x963(&key, pubkey_buf, &pubkey_buf_size);
	if (ret != 0) {
		print_debug("ECC public key x963 export failed! %d\n", ret);
		return -1;
	}
	print_debug("Exported public key to a buffer as x963 of size %d: ", pubkey_buf_size);
	print_hex_debug(pubkey_buf, PUBKEY_BUF_LEN);

	// IMPORT INTO NEW KEY
	print_debug("Importing public key into new object...");

	ecc_key key2; 

	ret = wc_ecc_init(&key2);
	if (ret != 0) {
		print_debug("Could not initialize new key");
		return -1;
	}
	
	ret = wc_ecc_import_x963_ex(pubkey_buf, pubkey_buf_size, &key2, ECC_CURVE);

    if (ret != 0) {
        print_debug("Ecc import x963 failed %d\n", ret);
        return -1;
    }

    print_debug("Succesfully imported public key!");

    // VERIFY HASH
    print_debug("Verifying signature with imported public key...");

    int stat = -1;

    ret = wc_ecc_verify_hash(sig_out, sigSz, hash_out, WC_SHA256_DIGEST_SIZE, &stat, &key2);

    if (ret != 0) {
        print_debug("Signature verification returned error %d\n", ret);
        return -1;
    }
    if (stat != 1) {
        print_debug("Signature verification rejected %d\n", stat);
        // return -1;
    } else {
    	print_debug("Signature verified successfully! ");
    }

    // dertest();

	// FREE STUFF
	print_debug("'Freeing' WC_RNG and ECC key... (?)");
	wc_ecc_key_free(&key);
	ret = wc_FreeRng(&mRng);
	print_debug("WC_RNG and ECC Key 'freed' with ret %d.", ret);


	return 0;

}

