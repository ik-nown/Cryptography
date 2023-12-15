#include <iostream>
#include <string>
using std::string;
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#endif
#include <fstream>
#include <locale>

// Cryptopp library
#include <cryptopp/cryptlib.h>
#include "cryptopp/sha3.h"
#include "cryptopp/sha.h"
#include "cryptopp/shake.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
using CryptoPP::FileSink;
using namespace std;

int main (int argc, char* argv[])
{   
//support for Vietnamese 
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    using namespace CryptoPP;

    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <hash_type> -i <option_input>" << std::endl;
        cerr << "Hash type: SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256" << std::endl; 
        cerr << "option input: screen, file";
        return 1;
    }
    unique_ptr<HashTransformation> hash;
    if (string(argv[1]) == "SHA3_224") {
        hash.reset(new SHA3_224);
    } else if (string(argv[1]) == "SHA3_256") {
        hash.reset(new SHA3_256);
    } else if (string(argv[1]) == "SHA3_384") {
        hash.reset(new SHA3_384);
    } else if (string(argv[1]) == "SHA3_512") {
        hash.reset(new SHA3_512);
    }
    else if (string(argv[1]) == "SHAKE128")  {
        hash.reset(new SHAKE128);
    }
    else if (string(argv[1]) == "SHAKE256") {
        hash.reset(new SHAKE256);
    }
    else {
        cerr << "Invalid hash type: " << argv[1] << endl;
        return 1;
    }

    std::cout << "Name: " << hash->AlgorithmName() << std::endl;
    std::cout << "Digest size: " << hash->DigestSize() << std::endl;
    std::cout << "Block size: " << hash->BlockSize() << std::endl;
    HexEncoder encoder(new FileSink(std::cout));

    //Open File and get message
    string choice = string(argv[3]);
    string message;
    if (choice == "screen") {
        std::cout<< "Enter your input: ";
        getline(cin, message);
    }
    else if (choice == "file") {
        cout<<"Enter your file name:";
        string fn; cin>>fn;
        ifstream file(fn, ios::binary);
        if(!file) {
            cerr << "Error opening file: " << argv[1] << std::endl;
            return 1;
        }
        else {
            std::string fileContents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            std::cout << "Do you want print the content of file? (y/n): ";
            message = fileContents;
            string yorn; std::cin >> yorn;
            if ( yorn == "y") {
                std::cout << "Message: " << fileContents << std::endl;   
            }
        }
    }
   
    std::string digest;
    // hashing 
    hash->Update((const CryptoPP::byte*)message.data(), message.size());
    digest.resize(hash->DigestSize());
    hash->TruncatedFinal((CryptoPP::byte*)&digest[0], digest.size()); // compute ouput
    //hash->Final((CryptoPP::byte*)&digest[0]);
    std::cout << "Digest: ";
    StringSource(digest, true, new Redirector(encoder));
    std::cout << std::endl;
}