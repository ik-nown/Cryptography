/*
The project contains: 
+ main.cpp - implement for user's option
+ AES_project.h - the header file for both AES_project.cpp and AES_runtime.cpp
+ AES_project.cpp - the code has encrypt/decrypt function ( for 8 modes) => file exe: AES_project.exe
+ AES_runtime.cpp - the code same AES_project.cpp but in 1000 times enc/dec => file exe: AES_runtime.exe 
*/

/* C++ libary*/
#include <iostream>
#include <fstream>
using std::endl;
#include <string>
using std::string;
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
#include "include\cryptopp\hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
#include "cryptopp\files.h"
#include "cryptopp\files.h"
// Count time
#include <chrono>
// include class
#include "AES_project.h"
#ifdef _WIN32
#include <windows.h>
#endif

int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    int modes;
    std::cout << "### Please enter your number to choice the mode of AES\n"
          << "1. ECB //  "
          << "2. CBC //  "
          << "3. OFB //  "
          << "4. CFB\n"
          << "5. CTR //  "
          << "6. XTS //  "
          << "7. CCM //  "
          << "8. GCM\n> ";
    std::cin >> modes;
    std::cin.ignore();
    string mode = check_mode(modes);
    AES_algo aes(mode);
    for (int i = 0; i < 2; i++)
    {
        int aescipher;
        std::cout << "### Would you like to encryption or decryption message:\n"
              << "1. Generate key and iv/ctr;\n"
              << "2. encryption;\n"
              << "3. decryption;\n"
              << "Please enter your number?\n> ";
        std::cin >> aescipher;
        std::cin.ignore();
        switch (aescipher)
        {
        case 1:
        {
            int choice;
            std::cout << "### Please enter your number to choice the option about generate key and iv:\n"
                  << "1. Random using CryptoPP::AutoSeededRandomPool;\n"
                  << "2. Input from screen;\n"
                  << "3. Input from file (using file name);\n> ";
            std::cin >> choice;
            std::cin.ignore();
            switch (choice)
            {
            case 1: // random
            {
                CryptoPP::AutoSeededRandomPool param;
                if (aes.mode != "XTS")
                {
                    param.GenerateBlock(aes.key, aes.keylength);
                    std::cout << "KEY_" << aes.mode << ": " << aes.byte2hex(aes.key) << '\n';
                }
                else
                { 
                    // key cho xts xử lí riêng
                    param.GenerateBlock(aes.key_XTS, aes.keylength * 2);
                    std::string hexOutput;
                    CryptoPP::StringSource(aes.key_XTS, aes.keylength * 2, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hexOutput)));
                    std::cout << "KEY_XTS: " << hexOutput << '\n';
                }
                if (mode != "ECB")
                {
                    param.GenerateBlock(aes.iv, aes.blocksize);
                    std::cout << "IV_" << aes.mode << ": " << aes.byte2hex(aes.iv) << '\n';
                }
                break;
            }
            case 2:
            {   
                string input_key, input_iv; // nhập vào
                std::cout << "### Enter your key (hex - 16 bytes (32 for XTS mode) : ";
                //std::cin.ignore();
                getline(std::cin, input_key);
                // xử lí key nhập từ bàn phím thành CryptoPP::byte
                if (input_key.length() != 32 && aes.mode != "XTS")
                {
                    std::cout << "Invalid KEY length";
                    exit(0);
                }
                else aes.hex2byte(input_key, aes.key); 
                if (aes.mode == "XTS" && input_key.length() != 64) //check
                {   
                    std::cout << "Invalid KEY_XTS length";
                    exit(0);
                }
                else aes.hex2byte(input_key, aes.key_XTS);
                
                // nếu mode khác ECB thì mới nhập iv
                if (aes.mode != "ECB")
                {
                    std::cout << "### Enter your iv( hex - 16 byte): ";
                    //std::cin.ignore();
                    getline(std::cin, input_iv);

                    // xử lí key nhập từ bàn phím thành CryptoPP::byte
                    if (input_iv.length() != 32)
                    {
                        std::cout << "Invalid IV length";
                        exit(0);
                    }
                    aes.hex2byte(input_iv, aes.iv);
                }
                break;
            }
            case 3:  // Key và iv từ file
            {
               
                string str;
                string path ;
                std::cout<<"Enter your file name: ";
                // std::cin.ignore();
                getline(std::cin, path);
                std::ifstream inputFile;
                // mở filefile
                try
                {
                    inputFile.open(path);
                }
                catch (const CryptoPP::Exception &e)
                {
                    std::cerr << e.what() << endl;
                    exit(0);
                }
                // lấy key từ file, xét hai trường hợp là XTS và các mode còn lại.
                getline(inputFile, str);
                if (aes.mode == "XTS")
                {   
                    if (str.length() != 64)
                    {
                        std::cout << "Invalid KEY XTS length";
                        exit(0);
                    }
                    else
                    {   
                        std::cout << "KEY_XTS: " << str << "\n";
                        aes.hex2byte(str, aes.key_XTS);
                    }
                }
                else
                {   

                    if (str.length() != AES::DEFAULT_KEYLENGTH *2 )
                    {
                        std::cout << "Invalid KEY length";
                        exit(0);
                    }
                    else
                    {
                        std::cout << "KEY_" << aes.mode << ": " << str << "\n";
                        aes.hex2byte(str, aes.key);
                    }
                }
                if (aes.mode != "ECB")
                {
                    getline(inputFile, str);
                    if (str.length() != AES::BLOCKSIZE * 2)
                    {
                        std::cout << "Invalid IV length";
                        exit(0);
                    }
                    std::cout << "IV_" << aes.mode << ": " << str << "\n";
                    aes.hex2byte(str, aes.iv);
                }
                inputFile.close();
                break;
            }
            }
            break;
        }
        case 2: // Encryption
        {
            std::cout << "### Please choice option (1,2):\n"
                  << "1. Input from screen.\n"
                  << "2. Input from file( file name).\n> ";
            int choice;
            std::cin >> choice;
            std::cin.ignore();
            // Nhập plaintext
            if (choice == 1)
            {
                string inputLine;
                std::cout << "Plainext: ";
                getline(std::cin, inputLine);
                aes.plaintext=inputLine;
                //std::cout<< aes.plaintext << endl;
            }
            else if (choice == 2)
            {
                std::cout << "### Enter your file name: ";
                string path;
                getline(std::cin, path);
                CryptoPP::FileSource(path.data(), true, new CryptoPP::StringSink(aes.plaintext));
                std::cout << "Plainext: " << aes.plaintext << endl;
            }
            aes.encryptAES();
            break;
        }
        case 3: //Decyption
        {
            std::cout << "### Please choice option (1,2):\n"
                  << "1. Input from screen.\n"
                  << "2. Input from file( file name).\n> ";
            int choice;
            std::cin >> choice;
            string base64Cipher;
            // Nhập ciphertext dưới dạng base64 và xử lí thành string
            if (choice == 1)
            {
                std::cout << "Ciphertext (base64 encoded): ";
                std::cin.ignore();
                getline(std::cin, base64Cipher);
            }
            else if (choice == 2)
            {
                string path;
                std::cout << "### Enter your file name: ";
                std::cin >> path;
                CryptoPP::FileSource(path.data(), true, new CryptoPP::StringSink(base64Cipher));
                std::cout << "Ciphertext (base64 encoded): " << base64Cipher << endl;
            }
            aes.decryptAES(base64Cipher);
            break;
        }
        default:
            std::cout << "Invalid input\n";
            exit(0);
            break;
        }
    }
    return 0;
}