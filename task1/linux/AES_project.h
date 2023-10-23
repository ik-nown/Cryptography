
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
    string mode;
    int ctr=0;
    wstring plaintext;
    wstring ciphertext;
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte key_XTS[AES::DEFAULT_KEYLENGTH*2];
    CryptoPP::byte iv[AES::BLOCKSIZE];
    
    AES_algo(string mode);
    wstring byte2hex(CryptoPP::byte byteArray[]);
    void hex2byte(std::string hex, CryptoPP::byte array[]);
    string hex2string(wstring hex);
    void process_output(string string, wstring state);
    //bool gen_key(int choice, wstring fn2option3);
    void encryptAES();
    void decryptAES(wstring hexCipher);
};
string check_mode(int mode);
wstring string_to_wstring(const std::string &str);
string wstring_to_string(const std::wstring &str);

#endif