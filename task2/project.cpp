// CPP lib
#include <iostream>
#include <fstream>
#include <iomanip>
#include<sstream>
using std::endl;
#include <string>
using std::string;
#include <cstdlib>
#include <cstdint>
using std::exit;
#include "assert.h"
#include <locale>
/**/
/* Set utf8 support for windows*/
#ifdef _WIN32
#include <windows.h>
#endif
/* Convert string <--> utf8*/
#include <locale>
#include <codecvt>
#include "CBC_mode.h"
#include "AES.h"

using namespace std;

vector<uint8_t> str2vector(string str);
string vector2str(vector<uint8_t> byteVector);
std::vector<uint8_t> hex2byte(std::string hexStr);
string byte2hex(vector<uint8_t> byteVector);
int main(int argc, char *argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    cout<< "###Encrytion and Decryption by AES CBC mode###\n";
    string plaintext, ciphertext, KEY, IV;
    cout << "Input your plaintext for CBC mode in 1 line: ";
    getline(cin, plaintext);
    cout<<"Length of Plaintext : " << plaintext.size()<<"\n";
    cout << "Enter your KEY (16/24/32 bytes): ";   
    //cin.ignore();
    getline(cin, KEY);
    cout << "Enter your IV (16 bytes): ";
    cin >> IV;
    //cin.ignore();
    cout<<"Length of KEY (bytes): " << KEY.size() <<"\n";

    /* chuyển thành vector để encrypt*/
    vector<uint8_t> byte_pl = str2vector(plaintext);
    vector<uint8_t> byte_key = str2vector(KEY);
    vector<uint8_t> byte_iv = str2vector(IV);
    /*tạo một đối tượng CBC mode*/
    CBC_mode mode = CBC_mode(byte_key, byte_iv);

    /*encrypting*/
    vector<uint8_t> enc_data = mode.cbc_encrypt(byte_pl);
    
    /*in ciphertext dưới dạng hex*/
    std::string hexString;
    hexString = byte2hex(enc_data);
    std::cout <<"Ciphertext (hex): "<< hexString << "\n";
    // /*decypting the encrypted data*/
    cout<<"Length of Ciphertext (bytes): " << enc_data.size() << '\n';
    cout<<"Input the cipher text (hex): "; 
    string input;
    cin.ignore();
    getline(cin, input);
    vector<uint8_t> dec_data = mode.cbc_decrypt(hex2byte(input)); 
    string recovered = vector2str(dec_data);
    cout<< "Recovered text CBC mode: "<< recovered;
    return 0;
} 

// Test key 128: "12345678abcdefgh"
// Test key 192: "12345678abcdefghvbnmfgds"
// Test key 256: "12345678abcdefghvbnmfgds12345678"

vector<uint8_t> str2vector(string str) {
    // Chuyển đổi string UTF-8 thành vector<uint8_t>
    std::vector<uint8_t> byteVector(str.begin(), str.end());
    return byteVector;
}

/*từ vector byte chuyển sang wstring*/
string vector2str(vector<uint8_t> byteVector){
    // Khởi tạo locale với codecvt
    std::locale loc(std::locale(), new std::codecvt_utf8<wchar_t>);

    // Chuyển đổi vector<uint8_t> thành chuỗi UTF-8
    std::string utf8Str(byteVector.begin(), byteVector.end());
    // Chuyển đổi chuỗi UTF-8 thành wstring
    return utf8Str;
}
/*từ hex chuyển sang vector byte*/
std::vector<uint8_t> hex2byte(std::string hexStr) {
    std::vector<uint8_t> byteVector;
    for (size_t i = 0; i < hexStr.size(); i += 2) {
        // Lấy cặp ký tự hex từ chuỗi UTF-8 và chuyển đổi thành giá trị uint8_t
        std::string byteStr = hexStr.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        byteVector.push_back(byte);
    }
    return byteVector;
}
string byte2hex(vector<uint8_t> byteVector){
    stringstream ss;
    string result;
    for (int i = 0; i < byteVector.size(); i++) {
        ss << hex << setw(2) << setfill('0') << (unsigned int) (byteVector[i] & 0xff);
    }
    result = ss.str();
    return result;
} 