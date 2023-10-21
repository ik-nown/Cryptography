// CPP lib
#include <iostream>
#include <fstream>
#include <iomanip>
#include<sstream>
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
#include "CBC_mode.h"
#include "AES.h"

using namespace std;

wstring string_to_wstring(const string &str);
string wstring_to_string(const wstring &str);
vector<uint8_t> wstr2vector(wstring wstr);
wstring vector2wstr(vector<uint8_t> byteVector);
std::vector<uint8_t> hex2byte(std::wstring hexWStr);
wstring byte2hex(vector<uint8_t> byteVector);
int main(int argc, char *argv[]) {
    #ifdef _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
    #endif

    wcout<< "###Encrytion and Decryption by AES CBC mode###\n";
    wstring plaintext, ciphertext, KEY, IV;
    wcout << "Input your plaintext for CBC mode in 1 line: ";
    getline(wcin, plaintext);
    wcout<<"Length of Plaintext : " << plaintext.size()<<"\n";
    wcout << "Enter your KEY (16/24/32 bytes): ";   
    wcin.ignore();
    getline(wcin, KEY);
    wcout << "Enter your IV (16 bytes): ";
    wcin >> IV;
    wcin.ignore();
    wcout<<"Length of KEY (bytes): " << KEY.size()/2<<"\n";

    /* chuyển thành vector để encrypt*/
    vector<uint8_t> byte_pl = wstr2vector(plaintext);
    vector<uint8_t> byte_key = wstr2vector(KEY);
    vector<uint8_t> byte_iv = wstr2vector(IV);
    /*tạo một đối tượng CBC mode*/
    CBC_mode mode = CBC_mode(byte_key, byte_iv);

    /*encrypting*/
    vector<uint8_t> enc_data = mode.cbc_encrypt(byte_pl);
    
    /*in ciphertext dưới dạng hex*/
    std::wstring hexString= byte2hex(enc_data);
    std::wcout <<"Ciphertext (hex): "<< hexString << "\n";
    // /*decypting the encrypted data*/
    wcout<<L"Length of Ciphertext (bytes): " << enc_data.size() << '\n';
    wcout<<"Input the cipher text (hex): "; 
    wstring input;
    wcin.ignore();
    getline(wcin, input);
    vector<uint8_t> dec_data = mode.cbc_decrypt(hex2byte(input)); //bug
    wstring recovered = vector2wstr(dec_data);
    wcout<< "Recovered text CBC mode: "<< recovered;
    return 0;
} 

// Test key 128: "12345678abcdefgh"
// Test key 192: "12345678abcdefghvbnmfgds"
// Test key 256: "12345678abcdefghvbnmfgds12345678"


// hỗ trợ tiếng việt.
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

vector<uint8_t> wstr2vector(wstring wstr) {
    string utf8Str = wstring_to_string(wstr);
    // Chuyển đổi string UTF-8 thành vector<uint8_t>
    std::vector<uint8_t> byteVector(utf8Str.begin(), utf8Str.end());
    
    return byteVector;
}
/*từ vector byte chuyển sang wstring*/
wstring vector2wstr(vector<uint8_t> byteVector){
    // Khởi tạo locale với codecvt
    std::locale loc(std::locale(), new std::codecvt_utf8<wchar_t>);

    // Chuyển đổi vector<uint8_t> thành chuỗi UTF-8
    std::string utf8Str(byteVector.begin(), byteVector.end());
    // Chuyển đổi chuỗi UTF-8 thành wstring
    return string_to_wstring(utf8Str);
}
/*từ hex chuyển sang vector byte*/
std::vector<uint8_t> hex2byte(std::wstring hexWStr) {
    // Chuyển wstring thành chuỗi UTF-8
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    std::string utf8Str = converter.to_bytes(hexWStr);

    std::vector<uint8_t> byteVector;
    for (size_t i = 0; i < utf8Str.size(); i += 2) {
        // Lấy cặp ký tự hex từ chuỗi UTF-8 và chuyển đổi thành giá trị uint8_t
        std::string byteStr = utf8Str.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        byteVector.push_back(byte);
    }

    return byteVector;
}
wstring byte2hex(vector<uint8_t> byteVector){
    stringstream ss;
    string result;
    for (int i = 0; i < byteVector.size(); i++) {
        ss << hex << setw(2) << setfill('0') << (unsigned int) (byteVector[i] & 0xff);
    }
    result = ss.str();
    return string_to_wstring(result);
} 