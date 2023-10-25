// CPP lib
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
#include <locale>

/* Convert string <--> utf8*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
// CryptoPP lib
#include "include/cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
#include <cryptopp/base64.h>
#include "cryptopp/filters.h"
#include "cryptopp/files.h"
// Count time
#include <chrono>
// include class
#include "AES_project.h"
using namespace std;
using namespace CryptoPP;
int main(int argc, char *argv[])
{
    #ifdef __linux__
	    std::locale::global(std::locale("C.UTF-8"));
    #endif

    int modes;
    cout << "### Please enter your number to choice the mode of AES\n"
          << "1. ECB //  "
          << "2. CBC //  "
          << "3. OFB //  "
          << "4. CFB\n"
          << "5. CTR //  "
          << "6. XTS //  "
          << "7. CCM //  "
          << "8. GCM\n> ";
    cin >> modes;
    cin.ignore();
    string mode = check_mode(modes);
    AES_algo aes(mode);
    for (int i = 0; i < 3; i++)
    {
        int aescipher;
        cout << "### Would you like to encryption or decryption message:\n"
              << "1. Generate key and iv/ctr;\n"
              << "2. encryption;\n"
              << "3. decryption;\n"
              << "Please enter your number?\n> ";
        cin >> aescipher;
        cin.ignore();
        switch (aescipher)
        {
        case 1:
        {
            int choice;
            cout << "### Please enter your number to choice the option about generate key and iv:\n"
                  << "1. Random using CryptoPP::AutoSeededRandomPool;\n"
                  << "2. Input from screen;\n"
                  << "3. Input from file (using file name);\n> ";
            cin >> choice;
            cin.ignore();
            switch (choice)
            {
            case 1:
            {
                CryptoPP::AutoSeededRandomPool param;
                if (aes.mode != "XTS")
                {
                    param.GenerateBlock(aes.key, AES::DEFAULT_KEYLENGTH);
                    string hexkey;
                    CryptoPP::StringSource(aes.key, AES::DEFAULT_KEYLENGTH, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hexkey)));
                    cout << "KEY_" << aes.mode << ": " << hexkey << '\n';
                }
                else
                { // key cho xts xử lí riêng
                    param.GenerateBlock(aes.key_XTS, AES::DEFAULT_KEYLENGTH * 2);
                    std::string hexOutput;
                    CryptoPP::StringSource(aes.key_XTS, AES::DEFAULT_KEYLENGTH * 2, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hexOutput)));
                    cout << "KEY_XTS: " << hexOutput << endl;
                }
                // mode khac ECB moi co IV
                if (mode != "ECB")
                {   
                    string hexiv;
                    param.GenerateBlock(aes.iv, AES::BLOCKSIZE);
                    CryptoPP::StringSource(aes.iv, AES::BLOCKSIZE, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hexiv)));
                    cout << "IV_" <<aes.mode << ": " << hexiv << endl;
                }
                break;
            }
            case 2: // key và iv nhập từ bàn phím
            {   
                string input_key, input_iv; // nhập vào
                cout << "### Enter your key (hex - 16 bytes (32 for XTS mode) : ";
                
                getline(cin, input_key);
                // từ key hex sang byte
                if (input_key.length() != AES::DEFAULT_KEYLENGTH * 2 && aes.mode != "XTS")
                {
                    cout << "Invalid KEY length";
                    exit(0);
                }
                else aes.hex2byte(input_key, aes.key);
                // neu mode là XTS thì check length == 32 bytes
                if (aes.mode == "XTS" && input_key.length() != 32 * 2)
                {
                    cout << "Invalid KEY_XTS length";
                    exit(0);
                }
                else aes.hex2byte(input_key, aes.key_XTS);
                
                // nếu mode khác ECB thì mới nhập iv
                if (aes.mode != "ECB")
                {
                    cout << "### Enter your iv( hex - 16 byte): ";
                    
                    getline(cin, input_iv);

                    // xử lí hex iv nhập từ bàn phím thành CryptoPP::byte
                    if (input_iv.length() != AES::BLOCKSIZE * 2)
                    {
                        cout << "Invalid IV length";
                        exit(0);
                    }
                    // str_iv = wstring_to_string(input_iv);
                    aes.hex2byte(input_iv, aes.iv);
                }
                break;
            }
            case 3:  // Key và iv từ file
            {
               
                string str;
                string path ;
                cout<<"Enter your file name: ";
                
                getline(cin, path);
                std::ifstream inputFile;
                // mở filefile
                try
                {
                    inputFile.open(path);
                }
                catch (const CryptoPP::Exception &e)
                {
                    wcerr << e.what() << endl;
                    exit(0);
                }
                // lấy key từ file, xét hai trường hợp là XTS và các mode còn lại.
                getline(inputFile, str);
                if (aes.mode == "XTS")
                {   
                    if (str.length() != 64)
                    {
                        cout << "Invalid KEY XTS length";
                        exit(0);
                    }
                    else
                    {   
                        cout << "KEY_XTS: " << str << "\n";
                        aes.hex2byte(str, aes.key_XTS);
                    }
                }
                else
                {   

                    if (str.length() != AES::DEFAULT_KEYLENGTH *2 )
                    {
                        cout << "Invalid KEY length";
                        exit(0);
                    }
                    else
                    {
                        cout << "KEY_" << aes.mode << ": " << str << "\n";
                        aes.hex2byte(str, aes.key);
                    }
                }
                if (aes.mode != "ECB")
                {
                    getline(inputFile, str);
                    if (str.length() != AES::BLOCKSIZE * 2)
                    {
                        cout << "Invalid IV length";
                        exit(0);
                    }
                    cout << "IV_" << aes.mode << ": " << str << "\n";
                    aes.hex2byte(str, aes.iv);
                }
                inputFile.close();
                break;
            }
            }
            break;
        }
        case 2: //Encryption 
        {
            cout << "### Please choice option (1,2):\n"
                  << "1. Input from screen.\n"
                  << "2. Input from file( file name).\n> ";
            int choice;
            cin >> choice;
            cin.ignore();
            if (choice == 1) // from screen
            {
                string inputLine;
                cout << "Plainext: ";
                getline(cin, aes.plaintext);  
            }
            else if (choice == 2)
            {
                cout << "### Enter your file name: ";
                string path;
                cin >> path;
                CryptoPP::FileSource(path.data(), true, new StringSink(aes.plaintext));
                cout << "Plainext: " << aes.plaintext;
            }
            aes.encryptAES();
            break;
        }
        case 3: //Decryption
        {
            cout  << "### Please choice option (1,2):\n"
                  << "1. Input from screen.\n"
                  << "2. Input from file( file name).\n> ";
            int choice;
            cin >> choice;
            string base64;
            if (choice == 1) // Nhập ciphertext dưới dạng base64
            {
                cout << "Ciphertext (in base64): ";
                cin.ignore();
                getline(cin, base64);
            }
            else if (choice == 2) // lấy ct từ file
            {
                string path;
                cout << "### Enter your file name: ";
                cin >> path;
                CryptoPP::FileSource(path.data(), true, new StringSink(base64));
                cout << "Ciphertext (base64 encoded): " << base64 << endl;
            }
            aes.decryptAES(base64);
            break;
        }
        default:
            cout << "Invalid input\n";
            exit(0);
            break;
        }
    }
    return 0;
}