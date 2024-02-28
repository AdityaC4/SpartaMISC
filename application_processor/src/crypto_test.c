#include "crypto_test.h"
#include "host_messaging.h"

#define ECC_CURVE			ECC_SECP256R1
#define PUBKEY_BUF_LEN		ECC_BUFSIZE
#define PUBKEY_LEN 			ECC_MAXSIZE+1
#define MAX_CERT_SIZE       4096

int create_keypair() {
	print_info("In create_keypair()");

	WC_RNG mRng;
	wc_InitRng(&mRng);

	int ret; 
	ecc_key key; 

	ret = wc_ecc_init(&key);
    if (ret == 0) {
        ret = wc_ecc_make_key_ex(&mRng, 32, &key, ECC_CURVE);
    }

    if (ret != 0) {
        print_debug("ecc make key failed %d\n", ret);
        return -1;
    }

    print_debug("Key generated");

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
	word32 sigSz;

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

