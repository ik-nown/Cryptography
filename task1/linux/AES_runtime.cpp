// C internal library
#include <iostream>
#include <fstream>
using std::endl;
using std::wcerr;
using std::wcin;
using std::wcout;
#include <string>
using std::string;
#include <cstdlib>
using std::exit;
#include "assert.h"
#include <chrono>
#include "AES_project.h"
// Cryptopp Librari
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include <cryptopp/default.h>
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;
#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;
// convert string
// Hex <---> Binary
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

// Base64 <---> Binary
#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

// Block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;
#include "cryptopp/aes.h"
using CryptoPP::AES;

// Mode of operations
#include "cryptopp/modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
#include "cryptopp/xts.h"
using CryptoPP::XTS;
#include "cryptopp/ccm.h"
using CryptoPP::CCM;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
// Ref: more here https://www.cryptopp.com/wiki/AEAD_Comparison

/* Convert string <--> utf8*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
#include <chrono>

using namespace std;
using namespace CryptoPP;

// hàm check option về mode của người dùng
string check_mode(int mode)
{
    switch (mode)
    {
    case 1:
        return "ECB";
        break;
    case 2:
        return "CBC";
        break;
    case 3:
        return "OFB";
        break;
    case 4:
        return "CFB";
        break;
    case 5:
        return "CTR";
        break;
    case 6:
        return "XTS";
        break;
    case 7:
        return "CCM";
    case 8:
        return "GCM";
    }
    return "1";
}

AES_algo::AES_algo(string mode)
{
    this->mode = mode;
};

void AES_algo::hex2byte(std::string hex, CryptoPP::byte array[])
{
    CryptoPP::HexDecoder decoder;
    std::string decodedString;
    decoder.Attach(new CryptoPP::StringSink(decodedString));
    decoder.Put(reinterpret_cast<const unsigned char *>(hex.data()), hex.size());
    decoder.MessageEnd();
    std::memcpy(array, decodedString.data(), decodedString.size());
}
// display and write to file output

void AES_algo::process_output(string state)
{
    std::string enc;
    string filename;
    if (state == "Ciphertext")
    {
        cout << "Enter your file name to save: ";
        cin.ignore();
        getline(cin, filename);
        CryptoPP::StringSource(this->ciphertext, true, new CryptoPP::Base64Encoder(new CryptoPP::FileSink(filename.c_str())));
    }
    else if (state == "Plaintext")
    {
        cout << state << ": " << this->plaintext<< "\n";
    }
}

void AES_algo::encryptAES()
{
#ifdef __linux__
	    std::locale::global(std::locale("C.UTF-8"));
#endif
    //  Mã hóa và in ra ciphertext
    std::string str_ct;
    string state = "Ciphertext";
    auto start = std::chrono::high_resolution_clock::now();
    if (this->mode == "ECB")
    {
        ECB_Mode<AES>::Encryption e;
        e.SetKey(this->key, keylength);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        }
    }
    else if (this->mode == "CBC")
    {

        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keylength, iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        }
    }
    else if (this->mode == "CFB")
    {

        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keylength, iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct))); // StreamTransformationFilter
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        }
    }
    else if (this->mode == "OFB")
    {

        OFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keylength, iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct))); // StreamTransformationFilter
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        }
    }
    else if (this->mode == "CTR")
    {

        CTR_Mode<AES>::Encryption e;
        // lấy giá trị của iv làm ctr.
        e.SetKeyWithIV(key, keylength, iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct))); // StreamTransformationFilter
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        }
    }
    else if (this->mode == "XTS")
    {

        XTS_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(this->key_XTS, sizeof(this->key_XTS), iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(enc, new StringSink(str_ct),
                                                                     StreamTransformationFilter::NO_PADDING)); // StreamTransformationFilter
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(enc, new StringSink(str_ct), StreamTransformationFilter::NO_PADDING));
        }
    }
    else if (this->mode == "CCM")
    {
        // default length iv = 12, can modify { 7, 8, 9, 10, 11, 12, 13 }
        // same in decryption function
        int iv_length = 12;
        CryptoPP::byte newIV[iv_length];
        std::memcpy(newIV, this->iv, 12);
        // default tag_Size =8, can modify { 4, 6, 8, 10, 12, 14, 16 }
        // same in decyption function
        const int tag_size = 8;
        CCM<AES, tag_size>::Encryption e;
        e.SetKeyWithIV(key, keylength, newIV, 12);
        e.SpecifyDataLengths(0, this->plaintext.size(), 0);
        StringSource ss1(this->plaintext, true, new AuthenticatedEncryptionFilter(e, new StringSink(str_ct))); // AuthenticatedEncryptionFilter
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            e.SetKeyWithIV(key,keylength, newIV, 12);
            e.SpecifyDataLengths(0, this->plaintext.size(), 0);
            StringSource ss1(this->plaintext, true, new AuthenticatedEncryptionFilter(e, new StringSink(str_ct))); // AuthenticatedEncryptionFilter
        }
    }
    else if (this->mode == "GCM")
    {

        GCM<AES>::Encryption e;
        e.SetKeyWithIV(this->key, keylength, this->iv, blocksize);
        StringSource(this->plaintext, true, new AuthenticatedEncryptionFilter(e, new StringSink(str_ct)));
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            e.SetKeyWithIV(this->key, keylength, this->iv, blocksize);
            StringSource(this->plaintext, true, new AuthenticatedEncryptionFilter(e, new StringSink(str_ct)));
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double averageTime = static_cast<double>(duration) / 1000.0;
    std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    process_output(state);
}

void AES_algo::decryptAES(string base64Cipher)
{
    std::string str_pl, str_ct, plain;
    StringSource ss(base64Cipher, true, new Base64Decoder( new StringSink(str_ct)));
    string state = "Plaintext";
    auto start = std::chrono::high_resolution_clock::now();
    if (this->mode == "ECB")
    {
        ECB_Mode<AES>::Decryption d;
        d.SetKey(key, keylength);
        StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        }
    }
    if (this->mode == "CBC")
    {

        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(this->key, keylength, iv);
        StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        }
    }
    if (this->mode == "OFB")
    {

        OFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keylength, iv);
        StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        }
    }
    if (this->mode == "CFB")
    {

        CFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keylength, iv);
        StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        }
    }
    if (this->mode == "CTR")
    {

        CTR_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keylength, iv);
        StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        }
    }
    if (this->mode == "XTS")
    {

        XTS_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key_XTS, sizeof(key_XTS), iv);
        StringSource ss(str_ct, true, new StreamTransformationFilter(dec, new StringSink(str_pl), StreamTransformationFilter::NO_PADDING));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(str_ct, true, new StreamTransformationFilter(dec, new StringSink(str_pl), StreamTransformationFilter::NO_PADDING));
        }
    }
    if (this->mode == "CCM")
    {

        const int TAG_SIZE = 8;
        CryptoPP::byte newIV[12];
        std::memcpy(newIV, this->iv, 12);
        CCM<AES, TAG_SIZE>::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), newIV, sizeof(newIV));
        d.SpecifyDataLengths(0, str_ct.size() - TAG_SIZE, 0);
        AuthenticatedDecryptionFilter df(d, new StringSink(str_pl));
        StringSource ss(str_ct, true, new Redirector(df));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; i++)
        {
            d.SetKeyWithIV(key, sizeof(key), newIV, sizeof(newIV));
            d.SpecifyDataLengths(0, str_ct.size() - TAG_SIZE, 0);
            AuthenticatedDecryptionFilter df(d, new StringSink(str_pl));
            StringSource ss(str_ct, true, new Redirector(df));
        }
    }

    if (this->mode == "GCM")
    {

        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, keylength, iv, blocksize);
        StringSource ss(str_ct, true, new AuthenticatedDecryptionFilter(d, new StringSink(str_pl))); // StreamTransformationFilter
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; i++)
        {
            d.SetKeyWithIV(key, keylength, iv, blocksize);
            StringSource ss(str_ct, true, new AuthenticatedDecryptionFilter(d, new StringSink(str_pl)));
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double averageTime = static_cast<double>(duration) / 1000.0;
    std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    process_output(state);
}
