#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;
#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
#include "cryptopp/pem.h"

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/cryptlib.h"
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
#include "cryptopp/filters.h"
#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using namespace std;
// using namespace CryptoPP;

// C++ library
#include <iostream>
#include <assert.h>
#include <string>
#include <chrono>
using std::string;
#include <exception>
using std::exception;
void Save(const char *filename, const BufferedTransformation &bt);
void Load(const char *filename, BufferedTransformation &bt);
void SavePublicKey(const char *filename, const CryptoPP::RSA::PublicKey &key);
void SavePrivateKey(const char *filename, const CryptoPP::RSA::PrivateKey &key);
void LoadPublicKey(const char *filename, CryptoPP::RSA::PublicKey &key);
void LoadPrivateKey(const char *filename, CryptoPP::RSA::PrivateKey &key);

bool key_gen(const char *filePriv, const char *filePub, char *choice)
{
    // define random generator
    AutoSeededRandomPool rng;
    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 3072);
    CryptoPP::RSA::PrivateKey priv(parameters);
    CryptoPP::RSA::PublicKey pub(parameters);
    string c = choice;
    if (c == "1")
    {
        SavePrivateKey(filePriv, priv); // Encode
        SavePublicKey(filePub, pub);
        return true;
    }
    else if (c == "2") // save to PEM
    {
        CryptoPP::FileSink public_key(filePub, true);
        PEM_Save(public_key, pub);
        FileSink private_key(filePriv, true);
        PEM_Save(private_key, priv);
        return true;
    }
    else
        return false;
}

bool encrypt(const char *filePublic, char *choice_input, char *choice_output)
{

    AutoSeededRandomPool rng;
    CryptoPP::RSA::PublicKey publicKey;
    string plaintext, encoded;
    // load key
    string fn = filePublic;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);

    if (extension == "pem" or extension == "PEM")
    {
        FileSource fs(filePublic, true);
        PEM_Load(fs, publicKey);
    }
    else if (extension == "der" or extension == "DER")
    {
        LoadPublicKey(filePublic, publicKey);
    }
    string choice= choice_input;
    // user chon nhap plaintext
    if (choice == "1")
    {

        cout << "Enter your message: ";
        getline(cin, plaintext);
    }
    // user chon nhap tu file
    else if (choice == "2")
    {
        string fn;
        cout << "Enter your file name: ";
        cin >> fn;
        FileSource(fn.data(), true, new StringSink(plaintext));
    }
    ////tien hanh encrypt
    choice.clear();
    RSAES_OAEP_SHA_Encryptor e(publicKey);
    StringSource ss1(plaintext, true,
                     new PK_EncryptorFilter(rng, e,
                                            new StringSink(encoded)) // PK_EncryptorFilter
    );                                                               // StringSource

    string base64;
    StringSource(encoded, true, new Base64Encoder(new StringSink(base64), false));
    choice= choice_output;
    if (choice == "1")
    {
        cout << "Ciphertext: " << base64 << endl;
        return true;
    }
    else if (choice == "2")
    {
        string output;
        cout << "Enter your file output: ";
        cin >> output;
        std::ofstream outputFile(output);
        outputFile << base64;
        outputFile.close();
        return true;
    }
    else
        return false;
}

bool decrypt(const char *filePrivate, char *choice_input, char *choice_output)
{

    AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey privateKey;
    string ciphertext, recovered;
    // load key from file
    string fn = filePrivate;
    size_t lastDotPos = fn.find_last_of('.');
    std::string extension = fn.substr(lastDotPos + 1);
    if (extension == "pem" or extension == "PEM")
    {
        CryptoPP::FileSource fs(filePrivate, true);
        PEM_Load(fs, privateKey);
    }
    else if (extension == "der" or extension == "DER")
    {
        LoadPrivateKey(filePrivate, privateKey);
    }
    string choice = choice_input;
    // nhap ciphertext
    string base64;
    if (choice == "1") // nhap tu keyboard
    {
        cout << "Enter yout ciphertext in base64: ";
        cin >> base64;
    }
    else if (choice == "2") // nhap tu file
    {
        string fn;
        cout << "Enter your file cipher: ";
        cin >> fn;
        FileSource(fn.data(), true, new StringSink(base64));
    }
    choice.clear();
    //// decode base64
    StringSource ss(base64, true,
                    new Base64Decoder(
                        new StringSink(ciphertext)) // Base64Decoder
    );                                              // StringSource

    //// tien hanh decrypt
    try
    {
        RSAES_OAEP_SHA_Decryptor d(privateKey);
        StringSource ss2(ciphertext, true,
                         new PK_DecryptorFilter(rng, d,
                                                new StringSink(recovered)) // PK_DecryptorFilter
        );                                                                 // StringSource
    }
    catch (const Exception &ex)
    {
        cout << ex.what();
    }
    choice = choice_output;
    if (choice == "1")
    {
        cout << "Plaintext: " << recovered << endl;
        return true;
    }
    else if (choice == "2")
    {
        string output;
        cout << "Enter your output file: ";
        cin >> output;
        ofstream outputFile(output);
        outputFile << recovered;
        outputFile.close();
        return true;
    }
    else
        return false;
}

int main(int argc, char *argv[])
{
#ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
#endif
    if (argc != 5)
    {
        cerr << "Usage: " << argv[0] << " <module>  [option]" << std::endl
             << "MODULE: decrypt, encrypt, key_gen" << endl
             << "OPTION for module:" << endl
             << "For key_gen: <choice> <filepriavte> <filepublic> " << endl
             << "              - fileprivate: path to save private key" << endl
             << "              - filepublic: path to save public key" << endl
             << "              - choice: 1-file DER or 2-file PEM" << endl
             << "For encrypt: <filepublic> <choice_input> <choice_output>" << endl
             << "              - filepublic: path to public key file" << endl
             << "              - choice_input: 1-from screen or 2-from file" << endl
             << "              - choice_output: 1-to screen or 2-to file" << endl
             << "For decrypt: <fileprivate> <choice_input>  <choice_output> " << endl
             << "              - fileprivate: path to save private key" << endl
             << "              - choice_input: 1-from screen or 2-from file" << endl
             << "              - choice_output: 1->to screan or 2-to file" << endl
             << "Example: ./rsa key_gen 2 private.pem public.pem " << endl
             << "         ./rsa encrypt public.pem 1 1" << endl
             << "         ./rsa decrypt private.der 2 2" << endl;
        return 1;
    }
    string module = argv[1];
    auto start_time = std::chrono::high_resolution_clock::now();
    
    if (module == "key_gen")
    {   
        bool check = key_gen(argv[3], argv[4], argv[2]);
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        if (check == true)
        {
            cout <<"Success generate key-pair!" << endl 
                 <<"Timer: " << duration.count() << " ms";
            return 1;
        }
        else
        {
            cout << "Failed generate key-pair!";
            return 0;
        }
    }
    else if (module== "encrypt")
    {
        bool check = encrypt(argv[2], argv[3], argv[4]);
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        if (check == true) {
            cout << "Successfull encryption" << endl 
                 <<"Timer: " << duration.count() << " ms";
        }
        else
        {
            cout << "Failed encryption";
        }
    }
    else if ((module == "decrypt"))
    {
        bool check = decrypt(argv[2], argv[3], argv[4]);
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        if (check == true)
        {   
            cout << "Successfull decryption!" << endl 
                 <<"Timer: " << duration.count() << " ms";
            return 1;
        }
        else
        {
            cout << "Fail decryption!";
        }
    }
    else cout<<"error";
}

void Save(const char *filename, const BufferedTransformation &bt)
{
    FileSink file(filename);

    bt.CopyTo(file);
    file.MessageEnd();
}

void Load(const char *filename, BufferedTransformation &bt)
{
    FileSource file(filename, true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}
// save publickey into binary format
void SavePublicKey(const char *filename, const CryptoPP::RSA::PublicKey &key)
{
    // http://www.cryptopp.com/docs/ref/class_byte_queue.html
    ByteQueue queue;
    key.DEREncodePublicKey(queue);

    Save(filename, queue);
}
// save private key into binary format
void SavePrivateKey(const char *filename, const CryptoPP::RSA::PrivateKey &key)
{
    ByteQueue queue;
    key.DEREncodePrivateKey(queue);

    Save(filename, queue);
}
// load private key in binary format
void LoadPrivateKey(const char *filename, CryptoPP::RSA::PrivateKey &key)
{
    // http://www.cryptopp.com/docs/ref/class_byte_queue.html
    ByteQueue queue;

    Load(filename, queue);
    key.BERDecodePrivateKey(queue, false /*optParams*/, queue.MaxRetrievable());
}
// load public key in binary format

void LoadPublicKey(const char *filename, CryptoPP::RSA::PublicKey &key)
{
    // http://www.cryptopp.com/docs/ref/class_byte_queue.html
    ByteQueue queue;

    Load(filename, queue);
    key.BERDecodePublicKey(queue, false /*optParams*/, queue.MaxRetrievable());
}