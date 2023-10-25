
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
#include "include\cryptopp\default.h"
#include "include\cryptopp\osrng.h"
using CryptoPP::byte;
#include "include\cryptopp\des.h"
using CryptoPP::DES;
#include "include\cryptopp\aes.h"
using CryptoPP::AES;


class AES_algo {
public:
    static const int keylength = AES::DEFAULT_KEYLENGTH, blocksize = AES::BLOCKSIZE;
    string mode;
    int ctr=0;
    string plaintext;
    string ciphertext;
    CryptoPP::byte key[keylength];
    CryptoPP::byte key_XTS[keylength*2];
    CryptoPP::byte iv[blocksize];
    
    AES_algo(string mode);
    string byte2hex(CryptoPP::byte byteArray[]);
    void hex2byte(std::string hex, CryptoPP::byte array[]);
    void process_output(std::string state);
    void encryptAES();
    void decryptAES(string hexCipher);
};
string check_mode(int mode);

#endif