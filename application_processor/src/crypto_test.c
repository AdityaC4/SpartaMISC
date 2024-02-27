#include "crypto_test.h"
#include "host_messaging.h"

#include <wolfssl/wolfcrypt/random.h>

int create_keypair() {
	print_info("In create_keypair()");

	WC_RNG mRng;
	wc_InitRng(&mRng);

	int ret; 
	ecc_key key; 

	ret = wc_ecc_init(&key);
    if (ret == 0) {
        ret = wc_ecc_make_key(&mRng, 32, &key);
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
	byte sig_out[256];
	word32 sigSz;

	print_debug("Signing hash with ECC key... ");
	ret = wc_ecc_sign_hash(hash_out, WC_SHA256_DIGEST_SIZE, sig_out, &sigSz, &mRng, &key);
	if (ret != 0) {
		print_debug("Error signing hash.");
		return -1;
	}
	print_debug("Signed hash with signature length %d:", sigSz);
	print_hex_debug(sig_out, sigSz);

	// Free stuff
	print_debug("'Freeing' WC_RNG and ECC key... (?)");
	wc_ecc_key_free(&key);
	ret = wc_FreeRng(&mRng);
	print_debug("WC_RNG and ECC Key 'freed' with ret %d.", ret);

	return 0;

}