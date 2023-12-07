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
    __declspec(dllexport) int verify(const char* filePublic, const char* filename, const char* signFile);
}


int verify(const char* filePublic, const char* filename, const char* signFile) {

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    BIO* bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, filePublic);
    string fn = filePublic;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);
    EVP_PKEY* publicKey = nullptr;
    if (extension == "pem" or extension == "PEM") {
        
        publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    else if (extension == "der" or extension == "DER") {
        publicKey = d2i_PUBKEY_bio(bio, nullptr);
        BIO_free(bio);
    }

    if (!publicKey) {
        return 1;
    }
    std::ifstream signatureFile(signFile, std::ios::binary);
    if (!signatureFile.is_open()) {
        return 2;
    }
    std::vector<unsigned char> signature((std::istreambuf_iterator<char>(signatureFile)), std::istreambuf_iterator<char>());
    signatureFile.close();
    std::ifstream originalFile(filename, std::ios::binary);
    if (!originalFile.is_open()) {
        return 3;
    }
    std::vector<unsigned char> originalContents((std::istreambuf_iterator<char>(originalFile)), std::istreambuf_iterator<char>());
    originalFile.close();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&originalContents[0], originalContents.size(), hash);
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    EVP_VerifyInit(mdCtx, EVP_sha256());
    EVP_VerifyUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH);
    if (EVP_VerifyFinal(mdCtx, &signature[0], signature.size(), publicKey) != 1) {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(publicKey);
        return 4;
    }
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(publicKey);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}