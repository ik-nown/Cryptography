#include "queue.h"
using CryptoPP::ByteQueue;
#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "sha.h"
using CryptoPP::SHA1;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
#include "pem.h"
#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "SecBlock.h"
using CryptoPP::SecByteBlock;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;
#include "base64.h"
using CryptoPP::Base64Encoder;
#include "hex.h"
using CryptoPP::HexEncoder;
#include "filters.h"
#include <string>
using std::string;

#include <exception>
using std::exception;

//standar cpp library

#include "cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

// C++ library
#include <iostream>
#include <assert.h>
#ifdef _WIN32
#include <windows.h>
#endif
// Def function
void Save(const char* filename, const BufferedTransformation& bt);
void Load(const char* filename, BufferedTransformation& bt);
void SavePublicKey(const char* filename, const RSA::PublicKey& key);
void SavePrivateKey(const char* filename, const RSA::PrivateKey& key);
void LoadPublicKey(const char* filename, RSA::PublicKey& key);
void LoadPrivateKey(const char* filename, RSA::PrivateKey& key);

extern "C" {
    __declspec(dllexport) void encrypt(const char* filePublic, const char* text, int choice_input, char* ciphertext);
}


void encrypt(const char* filePublic, const char* text, int choice_input, char* ciphertext) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    AutoSeededRandomPool rng;
    RSA::PublicKey publicKey;
    string plaintext, encoded;
    //load key 
    string fn = filePublic;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);

    if (extension == "pem" or extension == "PEM") {
        FileSource fs(filePublic, true);
        PEM_Load(fs, publicKey);
    }
    else if (extension == "der" or extension == "DER") {
        LoadPublicKey(filePublic, publicKey);
    }
    

    // user chon nhap plaintext
    if (choice_input == 1) {
        plaintext = text;
    }
    // user chon nhap tu file
    else if (choice_input == 2) {
        FileSource(text, true, new StringSink(plaintext));
        
    }
    
    

    ////tien hanh encrypt
    
    RSAES_OAEP_SHA_Encryptor e(publicKey);
    StringSource ss1(plaintext, true,
        new PK_EncryptorFilter(rng, e,
            new StringSink(encoded)
        ) // PK_EncryptorFilter
    ); // StringSource
    
    string base64;
    StringSource(encoded, true, new Base64Encoder(new StringSink(base64), false));

    std::copy(base64.begin(), base64.end(), ciphertext);
    ciphertext[(int)base64.size()] = 0;
}


void Save(const char* filename, const BufferedTransformation& bt)
{
    FileSink file(filename);

    bt.CopyTo(file);
    file.MessageEnd();
}

void Load(const char* filename, BufferedTransformation& bt)
{
    FileSource file(filename, true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}
// save publickey into binary format
void SavePublicKey(const char* filename, const RSA::PublicKey& key)
{
    // http://www.cryptopp.com/docs/ref/class_byte_queue.html
    ByteQueue queue;
    key.DEREncodePublicKey(queue);

    Save(filename, queue);
}
// save private key into binary format
void SavePrivateKey(const char* filename, const RSA::PrivateKey& key)
{
    ByteQueue queue;
    key.DEREncodePrivateKey(queue);

    Save(filename, queue);
}
// load private key in binary format
void LoadPrivateKey(const char* filename, RSA::PrivateKey& key)
{
    // http://www.cryptopp.com/docs/ref/class_byte_queue.html
    ByteQueue queue;

    Load(filename, queue);
    key.BERDecodePrivateKey(queue, false /*optParams*/, queue.MaxRetrievable());
}
// load public key in binary format  

void LoadPublicKey(const char* filename, RSA::PublicKey& key)
{
    // http://www.cryptopp.com/docs/ref/class_byte_queue.html
    ByteQueue queue;

    Load(filename, queue);
    key.BERDecodePublicKey(queue, false /*optParams*/, queue.MaxRetrievable());
}
