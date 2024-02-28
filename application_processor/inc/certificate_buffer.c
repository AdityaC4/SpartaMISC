#include "certificate_buffer.h"
#include "wolfssl/ssl.h"

int loadCertificateFromBuffer(WOLFSSL *ssl, const unsigned char *in, long sz, int format) {
    int ret;

    ret = wolfSSL_use_certificate_buffer(ssl, in, sz, format);
    if (ret != SSL_SUCCESS) {
        return 0;
    }

   // return ret;
  return 1;
}
