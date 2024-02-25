#ifndef CERTIFICATE_HEADER_H
#define CERTIFICATE_HEADER_H

#include "wolfssl/ssl.h"

// Function declaration for certificate loading
int loadCertificateFromBuffer(WOLFSSL *ssl, const unsigned char *in, long sz, int format);


#endif 
