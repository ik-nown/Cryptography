// OpenSSL library

#include "openssl/evp.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h> // Include for SHA256
#include <openssl/ecdsa.h>

// Cryptopp library
#include "files.h"
#include "rsa.h"
#include "osrng.h"
#include "eccrypto.h"
#include "oids.h"
#include "hex.h"
#include "files.h"
#include "filters.h"
#include "queue.h"
#include "oids.h"
using CryptoPP::ByteQueue;
using CryptoPP::BufferedTransformation;
#include "base64.h"
// C++ library
#include <fstream>
#include <iterator> // Include for std::istreambuf_iterator
#include <vector> // Include for std::vector
#include <iostream>
#include <assert.h>
#include <string>
#include <iomanip>
using std::string;
#ifdef _WIN32
#include <windows.h>
#endif


extern "C" {
    __declspec(dllexport) bool key_gen(const char* filePrivate, const char* filePublic, int choice);
}


bool key_gen(const char* filePrivate, const char* filePublic, int choice) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    CryptoPP::AutoSeededRandomPool rng;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1);
    EVP_PKEY_keygen(pctx, &pkey);

    int ec = EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, NULL);
    if (choice == 1) {
        // Save private key in BER format
        BIO* bioPrivate = BIO_new_file(filePrivate, "wb");
        i2d_PrivateKey_bio(bioPrivate, pkey);
        BIO_free(bioPrivate);

        // Save public key in BER format
        BIO* bioPublic = BIO_new_file(filePublic, "wb");
        i2d_PUBKEY_bio(bioPublic, pkey);
        BIO_free(bioPublic);
        return true;
    }
    else if (choice == 2) {

        BIO* bioPrivate = BIO_new_file(filePrivate, "w");
        PEM_write_bio_PrivateKey(bioPrivate, pkey, NULL, NULL, 0, NULL, NULL);
        BIO_free(bioPrivate);

        // Save public key
        BIO* bioPublic = BIO_new_file(filePublic, "w");
        PEM_write_bio_PUBKEY(bioPublic, pkey);
        BIO_free(bioPublic);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return true;

    }
    else return false;
}
