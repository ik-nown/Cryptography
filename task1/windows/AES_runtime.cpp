

// C internal library
#include <iostream>
#include <fstream>
using std::endl;
#include <string>
using std::string;
#include <cstdlib>
using std::exit;
#include "assert.h"
#include <chrono>
#include "AES_project.h"
// Cryptopp Librari
#include "include\cryptopp\files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "include\cryptopp\filters.h"
using CryptoPP::Redirector; // string to bytes
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
#include <cryptopp/default.h>
#include "include\cryptopp\osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include "include\cryptopp\cryptlib.h"
using CryptoPP::Exception;

// convert string
// Hex <---> Binary
#include "include\cryptopp\hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

// Base64 <---> Binary
#include "include\cryptopp\base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

// Block cipher
#include "include\cryptopp\des.h"
using CryptoPP::DES;
#include "include\cryptopp\aes.h"
using CryptoPP::AES;

// Mode of operations
#include "include\cryptopp\modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
#include "include\cryptopp\xts.h"
using CryptoPP::XTS;
#include "include\cryptopp\ccm.h"
using CryptoPP::CCM;
#include "include\cryptopp\gcm.h"
using CryptoPP::GCM;
// Ref: more here https://www.cryptopp.com/wiki/AEAD_Comparison

/* Set utf8 support for windows*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
/* Convert string <--> utf8*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
#include <chrono>

using namespace CryptoPP;
#ifdef _WIN32
#include <windows.h>
#endif
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
// byte array to hex encode
string AES_algo::byte2hex(CryptoPP::byte byteArray[])
{
    std::string hexOutput;
    StringSource(byteArray, AES::DEFAULT_KEYLENGTH, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hexOutput)));
    return hexOutput;
}
// hex string to byte data
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
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    std::string enc;
    string filename;
    if (state == "Ciphertext")
    {
        std::cout << "Enter your file name to save: ";
        getline(std::cin, filename);
        CryptoPP::StringSource(this->ciphertext, true, new CryptoPP::Base64Encoder(new CryptoPP::FileSink(filename.c_str())));
    }
    else if (state == "Plaintext")
    {
        std::cout << state << ": " << this->plaintext<< endl;
    }
}

void AES_algo::encryptAES()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    //  Mã hóa và in ra ciphertext
    std::string str_ct, cipher;
    string state = "Ciphertext";
    if (this->mode == "ECB")
    {
        auto start = std::chrono::high_resolution_clock::now();
        ECB_Mode<AES>::Encryption e;
        e.SetKey(this->key, AES::DEFAULT_KEYLENGTH);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (this->mode == "CBC")
    {
        auto start = std::chrono::high_resolution_clock::now();
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (this->mode == "CFB")
    {
        auto start = std::chrono::high_resolution_clock::now();
        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct))); // StreamTransformationFilter
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (this->mode == "OFB")
    {
        auto start = std::chrono::high_resolution_clock::now();
        OFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct))); // StreamTransformationFilter
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (this->mode == "CTR")
    {
        auto start = std::chrono::high_resolution_clock::now();
        CTR_Mode<AES>::Encryption e;
        // lấy giá trị của iv làm ctr.
        e.SetKeyWithIV(key, sizeof(key), iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct))); // StreamTransformationFilter
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (this->mode == "XTS")
    {
        auto start = std::chrono::high_resolution_clock::now();
        XTS_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(this->key_XTS, sizeof(this->key_XTS), iv);
        StringSource ss(this->plaintext,true, new StreamTransformationFilter(enc, new StringSink(str_ct),
                                                          StreamTransformationFilter::NO_PADDING)); // StreamTransformationFilter
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {
            StringSource ss(this->plaintext, true, new StreamTransformationFilter(enc, new StringSink(str_ct), StreamTransformationFilter::NO_PADDING));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        
        process_output( state);
        std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (this->mode == "CCM")
    {
        auto start = std::chrono::high_resolution_clock::now();
        // default length iv = 12, can modify { 7, 8, 9, 10, 11, 12, 13 }
        // same in decryption function
        CryptoPP::byte newIV[12];
        std::memcpy(newIV, this->iv, 12);
        // default tag_Size =8, can modify { 4, 6, 8, 10, 12, 14, 16 }
        // same in decyption function
        const int tag_size = 8;
        CCM<AES, tag_size>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, newIV, 12);
        e.SpecifyDataLengths(0, this->plaintext.size(), 0);
        StringSource ss1( this->plaintext, true ,new AuthenticatedEncryptionFilter( e, new StringSink( str_ct ))); // AuthenticatedEncryptionFilter
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {   
            e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, newIV, 12);
            e.SpecifyDataLengths(0, this->plaintext.size(), 0);
            StringSource ss1( this->plaintext, true,new AuthenticatedEncryptionFilter( e, new StringSink( str_ct ))); // AuthenticatedEncryptionFilter
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    }
    else if (this->mode == "GCM")
    {
        auto start = std::chrono::high_resolution_clock::now();
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(this->key, AES::DEFAULT_KEYLENGTH, this->iv, AES::BLOCKSIZE);
        StringSource(this->plaintext, true, new AuthenticatedEncryptionFilter(e, new StringSink(str_ct)));
        this->ciphertext = str_ct;
        for (int i = 0; i < 1000; i++)
        {   
            e.SetKeyWithIV(this->key, AES::DEFAULT_KEYLENGTH, this->iv, AES::BLOCKSIZE);
            StringSource(this->plaintext, true, new AuthenticatedEncryptionFilter(e, new StringSink(str_ct)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    }
}

void AES_algo::decryptAES(string base64Cipher)
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    auto start = std::chrono::high_resolution_clock::now();
    std::string str_pl;
    StringSource ss(base64Cipher, true, new Base64Decoder( new StringSink(this->ciphertext)));
    string state = "Plaintext";
    if (this->mode == "ECB")
    {
        ECB_Mode<AES>::Decryption d;
        d.SetKey(key, AES::DEFAULT_KEYLENGTH);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    }
    if (this->mode == "CBC")
    {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(this->key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
        
    }
    if (this->mode == "OFB")
    {
        OFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
         process_output(state);
        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
       
    }
    if (this->mode == "CFB")
    {
        CFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
        
    }
    if (this->mode == "CTR")
    {
        CTR_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
        
    }
    if (this->mode == "XTS")
    {
        XTS_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key_XTS, sizeof(key_XTS), iv);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(dec, new StringSink(str_pl), StreamTransformationFilter::NO_PADDING));
        this->plaintext = str_pl;
        std::cout<< str_pl << endl;
        for (int i = 0; i < 1000; ++i)
        {
            StringSource ss(this->ciphertext, true, new StreamTransformationFilter(dec, new StringSink(str_pl), StreamTransformationFilter::NO_PADDING));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::wcout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
    }
    if (this->mode == "CCM")
    {
        const int TAG_SIZE = 8;
        CryptoPP::byte newIV[12];
        std::memcpy(newIV, this->iv, 12);
        CCM<AES, TAG_SIZE>::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), newIV, sizeof(newIV));
        d.SpecifyDataLengths(0, this->ciphertext.size() - TAG_SIZE, 0);
        AuthenticatedDecryptionFilter df(d, new StringSink(str_pl));
        StringSource ss(this->ciphertext, true, new Redirector(df));
        this->plaintext = str_pl;
        for (int i = 0; i < 1000; i++)
        {   
            d.SetKeyWithIV(key, sizeof(key), newIV, sizeof(newIV));
            d.SpecifyDataLengths(0, this->ciphertext.size() - TAG_SIZE, 0);
            AuthenticatedDecryptionFilter df(d, new StringSink(str_pl));
            StringSource ss(this->ciphertext, true, new Redirector(df));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
        
    }
    if (this->mode == "GCM")
    {       
        GCM< AES >::Decryption d;
		d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
        StringSource ss(this->ciphertext, true, new AuthenticatedDecryptionFilter(d, new StringSink(str_pl))); // StreamTransformationFilter
        this->plaintext = str_pl;
        for (int i=0; i< 1000; i++) {
            d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
            StringSource ss(this->ciphertext, true, new AuthenticatedDecryptionFilter(d, new StringSink(str_pl)));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double averageTime = static_cast<double>(duration) / 1000.0;
        process_output(state);
        std::cout << "Average time for decryption over 1000 rounds: " << averageTime << " ms" << std::endl;
        
    }
}