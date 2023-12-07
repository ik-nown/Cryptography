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
    __declspec(dllexport) int sign(const char* filePrivate, const char* filename, const char* signFile);
}


int sign(const char* filePrivate, const char* filename, const char* signFile) {

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    BIO* bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, filePrivate);
    string fn = filePrivate;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);
    EVP_PKEY* privateKey = nullptr;
    // Load file private key
    try {
        if (extension == "pem" or extension == "PEM") {
            privateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
            BIO_free(bio);
        }
        else if (extension == "der" or extension == "DER") {
            privateKey = d2i_PrivateKey_bio(bio, nullptr);
            BIO_free(bio);
        }
    }
    catch (std::exception& ex) {
        return 1;
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];


    try {
        std::ifstream pdfFile(filename, std::ios::binary);
        std::vector<unsigned char> pdfContents((std::istreambuf_iterator<char>(pdfFile)), std::istreambuf_iterator<char>());
        SHA256(&pdfContents[0], pdfContents.size(), hash);
        pdfFile.close();
    }
    catch (std::exception& ex) {
        return 2;
    }

    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    EVP_SignInit(mdCtx, EVP_sha256());
    EVP_SignUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH);

    unsigned int signatureLen = EVP_PKEY_size(privateKey);
    std::vector<unsigned char> signature(signatureLen);

    if (!EVP_SignFinal(mdCtx, &signature[0], &signatureLen, privateKey)) {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(privateKey);
        return 3;
    }
    
    std::ofstream signaturefile(signFile, std::ios::binary);
    signaturefile.write(reinterpret_cast<const char*>(&signature[0]), signatureLen);
    signaturefile.close();

    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(privateKey);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}