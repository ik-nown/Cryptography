

// C internal library
#include <iostream>
#include <fstream>
using std::endl;
using std::wcerr;
using std::wcin;
using std::wcout;
#include <string>
using std::string;
using std::wstring;
#include <cstdlib>
using std::exit;
#include "assert.h"
#include <chrono>
#include </home/iknown/Documents/Cryptography-main/task1/AES_project.h>
// Cryptopp Librari
#include "cryptopp/files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/filters.h"
using CryptoPP::Redirector; // string to bytes
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
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

using namespace std;
using namespace CryptoPP;

wstring string_to_wstring(const string &str);
string wstring_to_string(const wstring &str);
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
wstring AES_algo::byte2hex(CryptoPP::byte byteArray[])
{
    std::string hexOutput;
    StringSource(byteArray, AES::DEFAULT_KEYLENGTH, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hexOutput)));
    return string_to_wstring(hexOutput);
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
// convert from hex string to unicode string
string AES_algo::hex2string(wstring hex)
{
    string str = wstring_to_string(hex);
    string decoded;
    StringSource(str, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}
// display to screen and write to file output

void AES_algo::process_output(string string, wstring state)
{
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#endif
    std::string enc;
    wstring wstr;
    wstring filename;
    if (state == L"Ciphertext")
    {
        CryptoPP::StringSource(string, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(enc)));
        wstr = string_to_wstring(enc);
        wcout << state << ": " << wstr << '\n';
    }
    else if (state == L"Plaintext")
    {
        wstr = string_to_wstring(string);
        wcout << state << ": " << wstr << "\n";
    }
    wcout << "Enter your file name to save: ";
    // wcin.ignore();
    getline(wcin, filename);
    std::ofstream outputFile;
    try
    {
        outputFile.open(wstring_to_string(filename));
        if (outputFile.is_open())
        {
            outputFile << wstring_to_string(wstr);
            outputFile.close();
        }
        else
        {
            wcerr << "Failed to open the output file." << '\n';
        }
    }
    catch (const CryptoPP::Exception &e)
    {
        wcerr << e.what() << '\n';
    }
    outputFile.close();
}

void AES_algo::encryptAES()
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#endif

    //  encryption and process output
    // base on user's mode
    std::string str_pl, str_ct;
    /* Convert plaintext to string*/
    str_pl = wstring_to_string(plaintext);
    wstring state = L"Ciphertext";
    /*Encrypt AES EBC mode*/
    if (this->mode == "ECB")
    {
        ECB_Mode<AES>::Encryption e;
        e.SetKey(this->key, AES::DEFAULT_KEYLENGTH);
        StringSource ss(str_pl, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        
    }
    /*Encrypt AES CBC mode*/
    else if (this->mode == "CBC")
    {

        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(str_pl, true, new StreamTransformationFilter(e, new StringSink(str_ct)));
        
    }
    /* Encrypt AES CFB mode */
    else if (this->mode == "CFB")
    {
        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(str_pl, true, new StreamTransformationFilter(e, new StringSink(str_ct))); // StreamTransformationFilter
        
    }
    /* Encrypt AES OFB mode */
    else if (this->mode == "OFB")
    {

        OFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(str_pl, true, new StreamTransformationFilter(e, new StringSink(str_ct))); // StreamTransformationFilter
        
    }
    /* Encrypt AES CTR mode */
    else if (this->mode == "CTR")
    {
        ;
        CTR_Mode<AES>::Encryption e;
        // lấy giá trị của iv làm ctr.
        e.SetKeyWithIV(key, sizeof(key), iv);
        StringSource ss(str_pl, true, new StreamTransformationFilter(e, new StringSink(str_ct))); // StreamTransformationFilter
        
    }
    /* Encrypt AES XTS mode, using key 32 bytes length */
    else if (this->mode == "XTS")
    {
        XTS_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(this->key_XTS, sizeof(this->key_XTS), iv);
        StringSource ss(str_pl, true, new StreamTransformationFilter(enc, new StringSink(str_ct),
                                                                     StreamTransformationFilter::NO_PADDING)); // StreamTransformationFilter

        
    }
    /* Encrypt AES CCM-AE  mode,  */
    else if (this->mode == "CCM")
    {

        // default length iv = 12, can modify { 7, 8, 9, 10, 11, 12, 13 }
        // same in decryption function
        CryptoPP::byte newIV[12];
        std::memcpy(newIV, this->iv, 12);
        // default tag_Size =8, can modify { 4, 6, 8, 10, 12, 14, 16 }
        // same in decyption function
        CCM<AES, 8>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, newIV, 12);
        e.SpecifyDataLengths(0, str_pl.size(), 0);
        StringSource ss1(str_pl, true, new AuthenticatedEncryptionFilter(e, new StringSink(str_ct)));
        
    }
    /* Encrypt AES GCM Filter mode */
    else if (this->mode == "GCM")
    {
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(this->key, AES::DEFAULT_KEYLENGTH, this->iv, AES::BLOCKSIZE);
        StringSource(str_pl, true, new AuthenticatedEncryptionFilter(e, new StringSink(str_ct)));   
    }
    process_output(str_ct, state);
}

void AES_algo::decryptAES(wstring hexCipher)
{
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#endif

    std::string str_pl, str_ct, plain;
    str_ct = hex2string(hexCipher);
    wstring state = L"Plaintext";
    if (this->mode == "ECB")
    {
        ECB_Mode<AES>::Decryption d;
        d.SetKey(key, AES::DEFAULT_KEYLENGTH);
        StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
    }
    if (this->mode == "CBC")
    {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(this->key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        
    }
    if (this->mode == "OFB")
    {
        OFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        
    }
    if (this->mode == "CFB")
    {
        CFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        
    }
    if (this->mode == "CTR")
    {
        CTR_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource ss(str_ct, true, new StreamTransformationFilter(d, new StringSink(str_pl)));
        
    }
    if (this->mode == "XTS")
    {
        XTS_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key_XTS, sizeof(key_XTS), iv);
        StringSource ss(str_ct, true, new StreamTransformationFilter(dec, new StringSink(str_pl), StreamTransformationFilter::NO_PADDING));
        
    }
    if (this->mode == "CCM")
    {
        const int TAG_SIZE = 8;
        CryptoPP::byte newIV[12];
        std::memcpy(newIV, this->iv, 12);
        CCM<AES, TAG_SIZE>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, newIV, 12);
        d.SpecifyDataLengths(0, str_ct.size() - TAG_SIZE, 0);
        AuthenticatedDecryptionFilter df(d, new StringSink(str_pl));
        StringSource ss2(str_ct, true, new Redirector(df));
        
    }
    if (this->mode == "GCM")
    {
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
        StringSource ss(str_ct, true, new AuthenticatedDecryptionFilter(d, new StringSink(str_pl)));
    }
    process_output(str_pl, state);
}

/*support for vietnamese language*/

wstring string_to_wstring(const string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

string wstring_to_string(const wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
