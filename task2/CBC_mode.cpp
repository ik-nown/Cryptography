// CPP lib
#include <iostream>
#include <fstream>
#include <vector>
using std::endl;
using std::wcerr;
using std::wcin;
using std::wcout;
#include <string>
using std::string;
using std::wstring;
#include <cstdlib>
#include <cstdint>
using std::exit;
#include "assert.h"
#include <locale>
/**/
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
#include <D:\School\HK3\MMH\Labs\lab2\AES\task\task2\CBC_mode.h>
#include <D:\School\HK3\MMH\Labs\lab2\AES\task\task2\AES.h>
using namespace std;
std::string wstring_to_bytes(std::wstring wstr)
{
    // Set up the conversion facet for UTF-16 to UTF-8
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    // Perform the conversion from wstring to string
    return converter.to_bytes(wstr);
}
/*CBC mode*/

CBC_mode::CBC_mode(std::vector<uint8_t> _key, std::vector<uint8_t> _iv){
    this->key = _key;
    this->iv = _iv;
};

/*string plaintext, block size default 64 bit = */
// padding plaintext
std::vector<uint8_t> CBC_mode::pkcs7_padding(const std::vector<uint8_t> &data)
{
    size_t padding_length = 16 - (data.size() % 16);
    std::vector<uint8_t> padded_data = data;
    for (size_t i = 0; i < padding_length; ++i)
    {   
        padded_data.push_back(static_cast<uint8_t>(padding_length));
    }
    return padded_data;
}
// padding plaintext
std::vector<uint8_t> CBC_mode::pkcs7_unpadding(const std::vector<uint8_t> &data)
{
    if (data.empty() || data.size() % 16 != 0)
    {
        throw std::runtime_error("Invalid PKCS7 padding.");
    }
    size_t padding_length = data[data.size() - 1];
    if (padding_length > 16)
    {
        throw std::runtime_error("Invalid PKCS7 padding.");
    }
    for (size_t i = data.size() - padding_length; i < data.size(); ++i)
    {
        if (data[i] != padding_length)
        {
            throw std::runtime_error("Invalid PKCS7 padding.");
        }
    }
    std::vector<uint8_t> unpadded_data(data.begin(), data.end() - padding_length);
    return unpadded_data;
}
std::vector<uint8_t> CBC_mode::cbc_encrypt(const std::vector<uint8_t> &plaintext)
{   
    AES aes = AES(key, key.size());
    // Apply PKCS7 padding
    std::vector<uint8_t> padded_data = pkcs7_padding(plaintext);
    std::vector<uint8_t> encrypted_data;
    std::vector<uint8_t> previous_block = iv;

    // Encrypt each block
    
    for (size_t i = 0; i < padded_data.size(); i += 16)
    {
        std::vector<uint8_t> block(16);
        for (size_t j = 0; j < 16; j++)
        {
            block[j] = padded_data[i + j] ^ previous_block[j];
        }
        // aes encrypt
        std::vector<uint8_t> encrypted_block = aes.encrypt(block);
        encrypted_data.insert(encrypted_data.end(), encrypted_block.begin(), encrypted_block.end());
        previous_block = encrypted_block;
    }
    
    // Prepend the IV to the ciphertext
    encrypted_data.insert(encrypted_data.begin(), iv.begin(), iv.end());
    // wcout<<encrypted_data.size()<<"\n";
    return encrypted_data;
}
// CBC decryption
std::vector<uint8_t> CBC_mode::cbc_decrypt(const std::vector<uint8_t> &ciphertext)
{   
    AES aes = AES(key, key.size());
    if (ciphertext.size() < 16 || ciphertext.size() % 16 != 0)
    {
        throw std::runtime_error("Invalid ciphertext length for CBC decryption.");
    }

    // Extract the IV from the ciphertext
    std::vector<uint8_t> decrypted_data;
    std::vector<uint8_t> previous_block = iv;

    // Decrypt each block
    for (size_t i = 16; i < ciphertext.size(); i += 16)
    {
        std::vector<uint8_t> block(ciphertext.begin() + i, ciphertext.begin() + i + 16);
        // aes decrypt function
        std::vector<uint8_t> decrypted_block = aes.decrypt(block);
        for (size_t j = 0; j < 16; j++)
        {
            decrypted_block[j] ^= previous_block[j];
        }
        decrypted_data.insert(decrypted_data.end(), decrypted_block.begin(), decrypted_block.end());
        previous_block = block;
    }

    // Remove PKCS7 padding
    std::vector<uint8_t> unpadded_data = pkcs7_unpadding(decrypted_data);
    return unpadded_data;
}