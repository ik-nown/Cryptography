#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <iostream>
#include <openssl/err.h>

bool verifyCertificate(X509* cert, STACK_OF(X509)* intermediateCerts, X509_STORE* store) {
    // Create a verification context
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, intermediateCerts);

    // Verify the certificate
    int result = X509_verify_cert(ctx);

    // Clean up
    X509_STORE_CTX_free(ctx);

    return result == 1;
}

void printPublicKeyHex(X509* cert) {
    EVP_PKEY* pubKey = X509_get_pubkey(cert);
    if (pubKey) {
        std::cout << "Subject Public Key Info:" << std::endl;
        int keyType = EVP_PKEY_id(pubKey);
        std::cout << "  Public Key Algorithm: " << OBJ_nid2ln(keyType) << std::endl;
        int keyBits = EVP_PKEY_bits(pubKey);
        std::cout <<"       Public-Key: " << keyBits << " bits \n";
        // Print the public key in HEX format
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, pubKey);

        BUF_MEM* bptr;
        BIO_get_mem_ptr(bio, &bptr);

        for (size_t i = 0; i < bptr->length; ++i) {
            printf("%02X", static_cast<unsigned char>(bptr->data[i]));
            if (i < bptr->length - 1) {
                if ((i + 1) % 32 == 0) {
                    std::cout << std::endl;
                } else {
                    std::cout << ":";
                }
            }
        }

        std::cout << std::endl;

        BIO_free(bio);
        EVP_PKEY_free(pubKey);
    } else {
        std::cerr << "Failed to retrieve the public key." << std::endl;
    }
}
int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    int choice;
    std::cout << "Enter cert's file format (1-DER/2-PEM): "; std::cin >> choice;
    std::string RootCACert, IntermediateCert, WebsiteCert;
    // Load the Root CA Cert
    std::cout << "Enter your RootCA Cert file: "; std::cin >> RootCACert;
    BIO* bioRoot = BIO_new(BIO_s_file());
    
    BIO_read_filename(bioRoot, RootCACert.c_str());
    X509* rootCACert = nullptr;
    if (choice == 1) {
        rootCACert = d2i_X509_bio(bioRoot, nullptr);
    }
    else if (choice == 2) {
        rootCACert = PEM_read_bio_X509(bioRoot, nullptr, nullptr, nullptr);
    }
    else {
        std::cout << "Can't open " <<  RootCACert << std::endl;
        BIO_free(bioRoot);
        return -1;
    }
    BIO_free(bioRoot);
    //std::cout << "test 2" << std::endl;

    // Load the Intermediate Cert
    std::cout << "Enter your Intermediate Cert file: "; std::cin >> IntermediateCert;
    BIO* intermediateFile = BIO_new(BIO_s_file());
    BIO_read_filename(intermediateFile, IntermediateCert.c_str()); // Use intermediateFile instead of bioRoot
    X509* intermediateCert = nullptr;
    STACK_OF(X509)* intermediateCerts = sk_X509_new_null();
    
    if (choice == 1) {
        intermediateCert = d2i_X509_bio(intermediateFile, nullptr);
    }
    else if (choice == 2) {
        intermediateCert = PEM_read_bio_X509(intermediateFile, nullptr, nullptr, nullptr);
    }
    else {
        std::cout << "Can't open " <<  IntermediateCert << std::endl;
        BIO_free(intermediateFile);
        return -1;
    }
    sk_X509_push(intermediateCerts, intermediateCert);
    BIO_free(intermediateFile);

    // Load the website's Cert
    std::cout << "Enter your website Cert file: "; std::cin >> WebsiteCert;
    BIO* bioWebsite = BIO_new(BIO_s_file());
    BIO_read_filename(bioWebsite, WebsiteCert.c_str());
    X509* websiteCert = nullptr;
    if (choice == 1) {
        websiteCert = d2i_X509_bio(bioWebsite, nullptr);
    }
    else if (choice == 2) {
        websiteCert = PEM_read_bio_X509(bioWebsite, nullptr, nullptr, nullptr);
    }
    else {
        std::cout << "Can't open " <<  WebsiteCert << std::endl;
        BIO_free(bioWebsite);
        return -1;
    }
   

    // Create a certificate store and add Root CA Cert
    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, rootCACert);

    // Verify the website's certificate
    bool isValid = verifyCertificate(websiteCert, intermediateCerts, store);

    // Print the result
    if (isValid) {
        std::cout << "Website certificate is valid. \n" << std::endl;
        std::cout << "Subject Name: " << X509_NAME_oneline(X509_get_subject_name(websiteCert), nullptr, 0) << std::endl;
        std::cout << "Issuer Name: " << X509_NAME_oneline(X509_get_issuer_name(websiteCert), nullptr, 0) << std::endl;
        printPublicKeyHex(websiteCert);
    } else {
        std::cerr << "Website certificate verification failed." << std::endl;
    }

    // Clean up
    sk_X509_pop_free(intermediateCerts, X509_free);
    BIO_free(bioWebsite);
    X509_free(rootCACert);
    X509_free(websiteCert);
    X509_STORE_free(store);

    return 0;
}
