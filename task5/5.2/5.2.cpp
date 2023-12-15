// CPP standard library
#include <iostream>
#include <windows.h>
#include <fstream>
#include <locale>

// OpenSSL library
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>

using namespace std;

void printValidity(X509* x509)
{
    ASN1_TIME* notBefore = X509_get_notBefore(x509);
    ASN1_TIME* notAfter = X509_get_notAfter(x509);
    std::cout << "Validity: \n";
    if (notBefore)
    {
        BIO* bio = BIO_new(BIO_s_mem());
        ASN1_TIME_print(bio, notBefore);
        char* buffer;
        long length = BIO_get_mem_data(bio, &buffer);

        std::cout << "Not Before: " << std::string(buffer, length) << std::endl;

        BIO_free(bio);
    }

    if (notAfter)
    {
        BIO* bio = BIO_new(BIO_s_mem());
        ASN1_TIME_print(bio, notAfter);
        char* buffer;
        long length = BIO_get_mem_data(bio, &buffer);

        std::cout << "Not After : " << std::string(buffer, length) << std::endl;

        BIO_free(bio);
    }
}

void printSignature(X509* x509)
{
    // Get the signature algorithm
    const X509_ALGOR* sigAlg = X509_get0_tbs_sigalg(x509);
    const ASN1_OBJECT* sigObj = nullptr;
    int sigType = 0;
    const void* sigValue = nullptr;

    X509_ALGOR_get0(&sigObj, &sigType, &sigValue, sigAlg);

    std::cout << "Signature Algorithm: ";
    if (sigObj)
    {
        const char* sigAlgName = OBJ_nid2ln(OBJ_obj2nid(sigObj));
        if (sigAlgName)
        {
            std::cout << sigAlgName << std::endl;
            // OPENSSL_free((void*)sigAlgName);
        }
    }

    //Get the signature
    const ASN1_BIT_STRING* signature = nullptr;
    X509_get0_signature(&signature, &sigAlg, x509);
    std::cout << "Signature:" << std::endl;
    if (signature)
    {   int count = 0;
        for (int i = 0; i < signature->length; ++i)
        {
            printf("%02X", signature->data[i]);
            count ++;
            if (i != signature->length -1)
            {
                std::cout <<":";
            }
            if (count == 18) {
                std::cout << std::endl;
                count = 0;
            }

        }
        
    }
}

int main (int argc, char* argv[])
{   

//support for Vietnamese 
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    OpenSSL_add_all_algorithms();
    std::cout<<"Choose your file format (DER/PEM): (1/2)\n";
    int choice; cin>>choice;
    std::cout<<"Enter your file name: ";
    string path; cin>>path;
    // READ CERTIFICATE FILE
    BIO* bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, path.c_str());
    X509* x509 = nullptr;
    
    if (choice == 1) {
        x509 = d2i_X509_bio(bio, nullptr);
    }
    else if (choice == 2) {
        x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    }
    else {
        cout<<"Invalid choosen.\n"; 
    }
    if (!x509) {
        std::cerr << "Error reading X.509 certificate." << std::endl;
        BIO_free(bio);
        return false;
        }
    BIO_free(bio);

    // Print the subject name and issuer name
    std::cout << "Subject Name: " << X509_NAME_oneline(X509_get_subject_name(x509), nullptr, 0) << std::endl;
    std::cout << "Issuer Name: " << X509_NAME_oneline(X509_get_issuer_name(x509), nullptr, 0) << std::endl;
    //print time of certificate
    printValidity(x509);
    cout<< endl;
    // Print siganture
    printSignature(x509);
    cout << std::endl;
    EVP_PKEY* publicKey = X509_get_pubkey(x509);
    // verify the signature
    int signatureValid = X509_verify(x509, publicKey);
    if (signatureValid == 1) {
        // print the public key
        EVP_PKEY_print_public_fp(stdout, publicKey, 0, nullptr);
        cout << std::endl;
    }
    else {
        cout << "Invalid signature." << endl;
    }
    // Clean up
    X509_free(x509);
    EVP_PKEY_free(publicKey);
}