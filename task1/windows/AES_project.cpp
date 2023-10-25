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
//  check option about mode of user
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
    StringSource(byteArray, keylength, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hexOutput)));
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
// display to screen and write to file output

void AES_algo::process_output(std::string state)
{   
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    std::string enc;
    std::string filename;
    std::cout << "###Display on screen or save to file:\n"
         <<"1. Display on screen.\n"
         <<"2. Save to file.\n >>";
    int choice;
    std::cin>> choice;
    switch (choice)
    {
    case 1: // in ra man hinh
        if (state == "Ciphertext")
        {
            CryptoPP::StringSource(this->ciphertext, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(enc)));
            std::cout << state << ": " << enc << endl;
        }
        else if (state == "Plaintext")
        {
            std::cout << state << ": " << this->plaintext<< "\n";
        }
        break;
    case 2: // luu vao file 
        std::cout << "Enter your file name to save: ";
        std::cin.ignore();
        getline(std::cin, filename);
        if ( state == "Ciphertext") {
            CryptoPP::StringSource(this->ciphertext, true, new CryptoPP::Base64Encoder(new CryptoPP::FileSink(filename.c_str())));
        }
        else if (state == "Plaintext") {
            CryptoPP::StringSource(this->plaintext, true, new CryptoPP::FileSink(filename.c_str()));
        }
        break;
    default:
        std::cout<<"Invalid option.";
        break;
    } 
}

void AES_algo::encryptAES()
{   
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    /*
    encryption and process output
    base on user's mode
    */
    string state = "Ciphertext";
    /*Encrypt AES EBC mode*/
    if (this->mode == "ECB")
    {
        ECB_Mode<AES>::Encryption e;
        e.SetKey(this->key, keylength);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(this->ciphertext)));
        process_output(state);
    }
    /*Encrypt AES CBC mode*/
    else if (this->mode == "CBC")
    {
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keylength, iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(this->ciphertext)));
        process_output(state);
    }
    /* Encrypt AES CFB mode */
    else if (this->mode == "CFB")
    {
        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keylength, iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(this->ciphertext))); // StreamTransformationFilter
        process_output(state);
    }
    /* Encrypt AES OFB mode */
    else if (this->mode == "OFB")
    {
        OFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, keylength, iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(this->ciphertext))); // StreamTransformationFilter
        process_output(state);  
    }
    /* Encrypt AES CTR mode */
    else if (this->mode == "CTR")
    {;
        CTR_Mode<AES>::Encryption e;
        // lấy giá trị của iv làm ctr.
        e.SetKeyWithIV(key, sizeof(key), iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(e, new StringSink(this->ciphertext))); // StreamTransformationFilter
        process_output(state);
    }
     /* Encrypt AES XTS mode, using key 32 bytes length */
    else if (this->mode == "XTS")
    {
        XTS_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(this->key_XTS, sizeof(this->key_XTS), iv);
        StringSource ss(this->plaintext, true, new StreamTransformationFilter(enc, new StringSink(this->ciphertext),
                                                          StreamTransformationFilter::NO_PADDING)); // StreamTransformationFilter
        process_output(state);
    }
     /* Encrypt AES CCM-AE  mode,  */
    else if (this->mode == "CCM")
    {
        /* 
        default length iv = 12, can modify { 7, 8, 9, 10, 11, 12, 13 }
        same in decryption function 
        */
        const int iv_length = 12;
        CryptoPP::byte newIV[iv_length];
        std::memcpy(newIV, this->iv, iv_length);
        /*
        default tag_Size =8, can modify { 4, 6, 8, 10, 12, 14, 16 }
        same in decyption function
        */
        const int tag_Size =8;
        CCM<AES, tag_Size>::Encryption e;
        e.SetKeyWithIV(key, keylength, newIV, 12);
        e.SpecifyDataLengths(0, this->plaintext.size(), 0);
        StringSource ss1(this->plaintext, true, new AuthenticatedEncryptionFilter(e, new StringSink(this->ciphertext)));
        process_output(state);
    }
     /* Encrypt AES GCM Filter mode */
    else if (this->mode == "GCM")
    {
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(this->key, keylength, this->iv, blocksize);
        StringSource(this->plaintext, true, new AuthenticatedEncryptionFilter(e, new StringSink(this->ciphertext)));
        process_output(state);  
    }
    
}

void AES_algo::decryptAES(string base64Cipher)
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    
    std::string  plain;
    StringSource ss(base64Cipher, true, new Base64Decoder( new StringSink(this->ciphertext)));
    string state = "Plaintext";
    /*Decryption ECB mode*/
    if (this->mode == "ECB")
    {
        ECB_Mode<AES>::Decryption d;
        d.SetKey(key, keylength);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(this->plaintext)));
        process_output(state);
    }
    /*Decryption CBC mode*/
    if (this->mode == "CBC")
    {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(this->key, keylength, iv);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(this->plaintext)));
        process_output(state);
    }
    /*Decryption OFB mode*/
    if (this->mode == "OFB")
    {
        OFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keylength, iv);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(this->plaintext))); 
        process_output(state);  
    }
    /*Decryption CFB mode*/
    if (this->mode == "CFB")
    {
        CFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keylength, iv);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(this->plaintext)));
        process_output(state);  
    }
    /*Decryption CTR mode*/
    if (this->mode == "CTR")
    {
        CTR_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, keylength, iv);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(d, new StringSink(this->plaintext)));
        process_output(state);  
    }
    /*Decryption XTS mode*/
    if (this->mode == "XTS")
    {
        XTS_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key_XTS, sizeof(key_XTS), iv);
        StringSource ss(this->ciphertext, true, new StreamTransformationFilter(dec, new StringSink(this->plaintext), 
                                                                            StreamTransformationFilter::NO_PADDING));
        process_output(state);  
    }
    /*Decryption CCM mode*/
    if (this->mode == "CCM")
    {
        const int TAG_SIZE = 8;
        CryptoPP::byte newIV[12];
        std::memcpy(newIV, this->iv, 12);
        CCM<AES, TAG_SIZE>::Decryption d;
        d.SetKeyWithIV(key, keylength, newIV, 12);
        d.SpecifyDataLengths(0, this->ciphertext.size() - TAG_SIZE, 0);
        AuthenticatedDecryptionFilter df( d, new StringSink( this->plaintext));
        StringSource ss2( this->ciphertext, true,new Redirector( df ));
        process_output(state);  
    }
    /*Decryption GCM mode*/
    if (this->mode == "GCM")
    {       
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, keylength, iv, blocksize);
        StringSource ss(this->ciphertext, true, new AuthenticatedDecryptionFilter(d, new StringSink(this->plaintext)) );
        process_output(state);  
    }
}