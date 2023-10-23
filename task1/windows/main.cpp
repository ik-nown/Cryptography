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
// CryptoPP lib
#include "include\cryptopp\hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

// Count time
#include <chrono>
// include class
#include "AES_project.h"

int main(int argc, char *argv[])
{
    #ifdef __linux__
        setlocale(LC_ALL, "");
    #elif _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
    #endif
    int modes;
    wcout << "### Please enter your number to choice the mode of AES\n"
          << "1. ECB //  "
          << "2. CBC //  "
          << "3. OFB //  "
          << "4. CFB\n"
          << "5. CTR //  "
          << "6. XTS //  "
          << "7. CCM //  "
          << "8. GCM\n> ";
    wcin >> modes;
    wcin.ignore();
    string mode = check_mode(modes);
    AES_algo aes(mode);
    for (int i = 0; i < 2; i++)
    {
        int aescipher;
        wcout << "### Would you like to encryption or decryption message:\n"
              << "1. Generate key and iv/ctr;\n"
              << "2. encryption;\n"
              << "3. decryption;\n"
              << "Please enter your number?\n> ";
        wcin >> aescipher;
        wcin.ignore();
        switch (aescipher)
        {
        case 1:
        {
            int choice;
            wcout << "### Please enter your number to choice the option about generate key and iv:\n"
                  << "1. Random using CryptoPP::AutoSeededRandomPool;\n"
                  << "2. Input from screen;\n"
                  << "3. Input from file (using file name);\n> ";
            wcin >> choice;
            wcin.ignore();
            switch (choice)
            {
            case 1:
            {
                CryptoPP::AutoSeededRandomPool param;
                if (aes.mode != "XTS")
                {
                    param.GenerateBlock(aes.key, AES::DEFAULT_KEYLENGTH);
                    wcout << L"KEY_" << string_to_wstring(aes.mode) << ": " << aes.byte2hex(aes.key) << '\n';
                }
                else
                { // key cho xts xử lí riêng
                    param.GenerateBlock(aes.key_XTS, AES::DEFAULT_KEYLENGTH * 2);
                    std::string hexOutput;
                    CryptoPP::StringSource(aes.key_XTS, AES::DEFAULT_KEYLENGTH * 2, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hexOutput)));
                    wcout << "KEY_XTS: " << string_to_wstring(hexOutput) << '\n';
                }
                if (mode != "ECB")
                {
                    param.GenerateBlock(aes.iv, AES::BLOCKSIZE);
                    wcout << "IV_" << string_to_wstring(aes.mode) << ": " << aes.byte2hex(aes.iv) << '\n';
                }
                break;
            }
            case 2:
            {   
                wstring input_key, input_iv; // nhập vào
                string str_key, str_iv;
                wcout << "### Enter your key (hex - 16 bytes (32 for XTS mode) : ";
                wcin.ignore();
                getline(wcin, input_key);
                str_key = wstring_to_string(input_key);
                // xử lí key nhập từ bàn phím thành CryptoPP::byte
                if (input_key.length() != AES::DEFAULT_KEYLENGTH * 2 && aes.mode != "XTS")
                {
                    wcout << "Invalid KEY length";
                    exit(0);
                }
                else aes.hex2byte(str_key, aes.key);
                if (aes.mode == "XTS" && input_key.length() != 32 * 2)
                {   
                    wcout << "Invalid KEY_XTS length";
                    exit(0);
                }
                else aes.hex2byte(str_key, aes.key_XTS);
                
                
                // nếu mode khác ECB thì mới nhập iv
                if (aes.mode != "ECB")
                {
                    wcout << "### Enter your iv( hex - 16 byte): ";
                    wcin.ignore();
                    getline(wcin, input_iv);

                    // xử lí key nhập từ bàn phím thành CryptoPP::byte
                    if (input_iv.length() != AES::BLOCKSIZE * 2)
                    {
                        wcout << "Invalid IV length";
                        exit(0);
                    }
                    str_iv = wstring_to_string(input_iv);
                    aes.hex2byte(str_iv, aes.iv);
                }
                break;
            }
            case 3:
            {
                // Key và iv từ file
                string str;
                wstring path;
                wcout<<"Enter your file name: ";
                wcin.ignore();
                getline(wcin, path);
                std::ifstream inputFile;
                // mở filefile
                try
                {
                    inputFile.open(wstring_to_string(path));
                }
                catch (const CryptoPP::Exception &e)
                {
                    wcerr << e.what() << '\n';
                    exit(0);
                }
                // lấy key từ file, xét hai trường hợp là XTS và các mode còn lại.
                getline(inputFile, str);
                if (aes.mode == "XTS")
                {
                    if (sizeof(str) != 32*2)
                    {
                        wcout << "Invalid KEY XTS length";
                        exit(0);
                    }
                    else
                    {
                        wcout << "KEY_XTS: " << string_to_wstring(str) << "\n";
                        aes.hex2byte(str, aes.key_XTS);
                    }
                }
                else
                {
                    if (sizeof(str) != AES::DEFAULT_KEYLENGTH * 2)
                    {
                        wcout << "Invalid KEY length";
                        exit(0);
                    }
                    else
                    {
                        wcout << "KEY_" << string_to_wstring(aes.mode) << ": " << string_to_wstring(str) << "\n";
                        aes.hex2byte(str, aes.key);
                    }
                }
                if (aes.mode != "ECB")
                {
                    getline(inputFile, str);
                    if (sizeof(str) != AES::BLOCKSIZE * 2)
                    {
                        wcout << L"Invalid IV length";
                        exit(0);
                    }
                    wcout << "IV_" << string_to_wstring(aes.mode) << ": " << string_to_wstring(str) << "\n";
                    aes.hex2byte(str, aes.iv);
                }
                inputFile.close();
                break;
                
            }
            }
            break;
        }
        case 2:
        {
            wcout << "### Please choice option (1,2):\n"
                  << "1. Input from screen.\n"
                  << "2. Input from file( file name).\n> ";
            int choice;
            wcin >> choice;
            wcin.ignore();
            // Nhập plaintext
            if (choice == 1)
            {
                wstring inputLine;
                wcout << "Enter END to finish.\n";
                wcout << "Plainext: ";
                while (true)
                {
                    wcin.ignore();
                    getline(wcin, inputLine);
                    if (inputLine == L"END")
                    {
                        break; // Kết thúc khi gặp 'END'
                    }
                    aes.plaintext += inputLine + L"\n";
                }
                
            }
            // nhận nhiều dòng
            else if (choice == 2)
            {
                wcout << L"### Enter your file name: ";
                wstring path;
                wcin.ignore();
                getline(wcin, path);
                std::string str;
                std::ifstream inputFile;
                // Mở file
                try
                {
                    inputFile.open(wstring_to_string(path));
                }
                catch (const CryptoPP::Exception &e)
                {
                    wcerr << e.what() << L'\n';
                    exit(0);
                }
                str.assign((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
                aes.plaintext = string_to_wstring(str);
                inputFile.close();
            }
            aes.encryptAES();
            break;
        }
        case 3:
        {
            wcout << "### Please choice option (1,2):\n"
                  << "1. Input from screen.\n"
                  << "2. Input from file( file name).\n> ";
            int choice;
            wcin >> choice;
            wcin.ignore();
            wstring hexCipher;
            // Nhập ciphertext dưới dạng hex và xử lí thành string
            if (choice == 1)
            {
                wcout << "Ciphertext (in hex): ";
                wcin.ignore();
                getline(wcin, hexCipher);
            }
            else if (choice == 2)
            {
                wstring path;
                wstring line;
                wcout << "### Enter your file name: ";
                wcin.ignore();
                getline(wcin, path);
                std::wifstream inputFile;
                // mở filefile
                try
                {
                    inputFile.open(wstring_to_string(path));
                }
                catch (const CryptoPP::Exception &e)
                {
                    wcerr << e.what() << '\n';
                    exit(0);
                }
                while (std::getline(inputFile, line))
                {
                    hexCipher += line;
                }
                inputFile.close();
            }
            aes.decryptAES(hexCipher);
            break;
        }
        default:
            wcout << "Invalid input\n";
            exit(0);
            break;
        }
    }
    return 0;
}