//CryptoPP library

#include "cryptopp\rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "cryptopp\sha.h"
using CryptoPP::SHA1;

#include "cryptopp\filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "cryptopp\files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp\osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp\SecBlock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp\cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;
#include "cryptopp\base64.h"
using CryptoPP::Base64Encoder;
#include "cryptopp\hex.h"
using CryptoPP::HexEncoder;
#include "cryptopp\filters.h"
#include <string>
using std::string;

#include <exception>
using std::exception;

//standar cpp library

#include <iostream>
#include <assert.h>
#ifdef _WIN32
#include <windows.h>
#endif
int main(int argc, char* argv[])
{   
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif  
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        //sửa length 1024 -> 3072
        parameters.GenerateRandomWithKeySize( rng, 3072 );

        // tạo pubkey và prikey
        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );
        //sửa plaintext
        string plain="22520064", cipher, recovered;
        
        // Encryption
        RSAES_OAEP_SHA_Encryptor e(publicKey );

        StringSource( plain, true,
            new PK_EncryptorFilter( rng, e,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource
        // string base64Cipher, hexCipher;
        // StringSource(cipher, true, new Base64Encoder( new StringSink(base64Cipher)));
        // StringSource(cipher, true, new HexEncoder( new StringSink(hexCipher)));
        // std::cout<< "Ciphertext in base64: " <<base64Cipher << std::endl;
        // std::cout<< "Ciphertext in hex: " << hexCipher << std::endl;

        // Decryption
        RSAES_OAEP_SHA_Decryptor d( privateKey );

        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, d,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource

        std::cout<< recovered << std::endl;
	return 0;
}

