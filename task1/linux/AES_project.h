
#ifndef AES_project_H
#define AES_project_H
//CPP lib
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
#include <string>
using std::string;
using std::wstring;
// CryptoPP lib
#include "cryptopp/default.h"
#include "cryptopp/osrng.h"
using CryptoPP::byte;
#include "cryptopp/des.h"
using CryptoPP::DES;
#include "cryptopp/aes.h"
using CryptoPP::AES;


class AES_algo {
public:
    int keylength=AES::DEFAULT_KEYLENGTH, blocksize= AES::BLOCKSIZE;
    string mode;
    int ctr=0;
    string plaintext;
    string ciphertext;
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte key_XTS[AES::DEFAULT_KEYLENGTH*2];
    CryptoPP::byte iv[AES::BLOCKSIZE];
    
    AES_algo(string mode);
    void hex2byte(std::string hex, CryptoPP::byte array[]);
    void process_output(std::string state);
    void encryptAES();
    void decryptAES(string hexCipher);
};
string check_mode(int mode);

#endif