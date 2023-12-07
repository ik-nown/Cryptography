// OpenSSL library

#include "openssl/evp.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h> // Include for SHA256
#include <openssl/ecdsa.h>

// Cryptopp library
#include "cryptopp/files.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/queue.h"
#include "cryptopp/oids.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::ByteQueue;
#include "cryptopp/base64.h"
// C++ library
#include <fstream>
#include <iterator> // Include for std::istreambuf_iterator
#include <vector>   // Include for std::vector
#include <iostream>
#include <assert.h>
#include <string>
#include <iomanip>
#include <chrono>
using std::string;

bool key_gen(char* choice, const char* filePrivate, const char* filePublic)
{

    CryptoPP::AutoSeededRandomPool rng;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1);
    EVP_PKEY_keygen(pctx, &pkey);
    string c = choice;
    if (c == "1")
    {
        // Save private key in DER format
        BIO *bioPrivate = BIO_new_file(filePrivate, "wb");
        i2d_PrivateKey_bio(bioPrivate, pkey);
        BIO_free(bioPrivate);

        // Save public key in DER format
        BIO *bioPublic = BIO_new_file(filePublic, "wb");
        i2d_PUBKEY_bio(bioPublic, pkey);
        BIO_free(bioPublic);
        return true;
    }
    else if (c == "2")
    {

        BIO *bioPrivate = BIO_new_file(filePrivate, "w");
        PEM_write_bio_PrivateKey(bioPrivate, pkey, NULL, NULL, 0, NULL, NULL);
        BIO_free(bioPrivate);

        // Save public key
        BIO *bioPublic = BIO_new_file(filePublic, "w");
        PEM_write_bio_PUBKEY(bioPublic, pkey);
        BIO_free(bioPublic);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return true;
    }
    else
        return false;
}
bool sign(const char* filePrivate, char* choice,  const char* signFile)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    BIO *bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, filePrivate);
    string fn = filePrivate;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);
    EVP_PKEY *privateKey = nullptr;
    // Load file private key
    try
    {
        if (extension == "pem" or extension == "PEM")
        {
            privateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
            BIO_free(bio);
        }
        else if (extension == "der" or extension == "DER")
        {
            privateKey = d2i_PrivateKey_bio(bio, nullptr);
            BIO_free(bio);
        }
    }
    catch (std::exception &ex)
    {
        return 0;
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    string c = choice;
    // lay noi dung tu man hinh
    if (c == "1")
    {
    }
    // doc noi dung file can sign
    else if (c == "2")
    {   
        string filename;
        std::cout << "Enter your file name: "; std::cin>>filename;
        try
        {
            std::ifstream pdfFile(filename, std::ios::binary);
            std::vector<unsigned char> pdfContents((std::istreambuf_iterator<char>(pdfFile)), std::istreambuf_iterator<char>());
            SHA256(&pdfContents[0], pdfContents.size(), hash);
            pdfFile.close();
        }
        catch (std::exception &ex)
        {
            return 0;
        }
    }

    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_SignInit(mdCtx, EVP_sha256());
    EVP_SignUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH);

    unsigned int signatureLen = EVP_PKEY_size(privateKey);
    std::vector<unsigned char> signature(signatureLen);

    if (!EVP_SignFinal(mdCtx, &signature[0], &signatureLen, privateKey))
    {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(privateKey);
        return 0;
    }
    // ghi signature vao file
    std::ofstream signaturefile(signFile, std::ios::binary);
    signaturefile.write(reinterpret_cast<const char *>(&signature[0]), signatureLen);
    signaturefile.close();

    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(privateKey);
    EVP_cleanup();
    ERR_free_strings();
    return 1;
}

bool verify(const char* filePublic, const char* filename, const char* signFile)
{

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    BIO *bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, filePublic);
    string fn = filePublic;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);
    EVP_PKEY *publicKey = nullptr;
    if (extension == "pem" or extension == "PEM")
    {
        publicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    else if (extension == "der" or extension == "DER")
    {
        publicKey = d2i_PUBKEY_bio(bio, nullptr);
        BIO_free(bio);
    }

    if (!publicKey)
    {
        return 0;
    }
    std::ifstream signatureFile(signFile, std::ios::binary);
    if (!signatureFile.is_open())
    {
        return 0;
    }
    std::vector<unsigned char> signature((std::istreambuf_iterator<char>(signatureFile)), std::istreambuf_iterator<char>());
    signatureFile.close();
    std::ifstream originalFile(filename, std::ios::binary);
    if (!originalFile.is_open())
    {
        return 0;
    }
    std::vector<unsigned char> originalContents((std::istreambuf_iterator<char>(originalFile)), std::istreambuf_iterator<char>());
    originalFile.close();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&originalContents[0], originalContents.size(), hash);
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    EVP_VerifyInit(mdCtx, EVP_sha256());
    EVP_VerifyUpdate(mdCtx, hash, SHA256_DIGEST_LENGTH);
    
    if (EVP_VerifyFinal(mdCtx, &signature[0], signature.size(), publicKey) != 1)
    {
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(publicKey);
        return 0;
    }
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(publicKey);
    EVP_cleanup();
    ERR_free_strings();
    return 1;
}
int main(int argc, char *argv[])
{
#ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
#endif
    if (argc != 5)
    {
        std::cerr << "Usage: " << argv[0] << " <module> [input1] [input2] [input3] " << std::endl
                  << "MODULE: key_gen, sign, verify" << std::endl
                  << "for key_gen: <choice> <filePrivate> <filePublic>" << std::endl
                  << "            - choice: 1 for DER or 2 for PEM" << std::endl
                  << std::endl
                  << "for sign: <filePrivate> <choice> <signFile>" << std::endl
                  << "            - choice: 1-input from screen  or 2-input from file" << std::endl
                  << "for verify: <filePublic> <fileName> <signFile>" << std::endl
                  << "            - filename: file want to verify" << std::endl;
        return 0;
    }
    auto start_time = std::chrono::high_resolution_clock::now();
    string module = argv[1];
    if (module == "key_gen") {
        bool check = key_gen(argv[2], argv[3], argv[4]);
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        if (check == true) {
            std::cout<< "Success generate key-pair!"<<std::endl;
            std::cout<<"Timer: " << duration.count() << std::endl;
            return 1;
        }
        else {
            std::cout<<"Fail generate key-pair!" << std::endl;
            return 0;
        }
    }
    else if (module == "sign") {
        bool check = sign(argv[2], argv[3], argv[4]);
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        if (check == true) {
            std::cout<< "Successfull sign!"<<std::endl;
            std::cout<<"Timer: " << duration.count() << std::endl;
            return 1;
        }
        else {
            std::cout<<"Fail sign!" << std::endl;
            return 0;
        }

    }
    else if (module == "verify") {
        bool check = verify(argv[2], argv[3], argv[4]);
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        if (check == true) {
            std::cout<< "Valid signature!"<<std::endl;
            std::cout<<"Timer: " << duration.count() << std::endl;
            return 1;
        }
        else {
            std::cout<<"Invalid signature!" << std::endl;
            return 0;
        }
    }
}