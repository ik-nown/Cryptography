#ifndef CBC_MODE_H
#define CBC_MODE_H

#include <vector>
#include <cstdlib>
#include <cstdint>

class CBC_mode {
public:
    std::vector<uint8_t> key;
    std::vector<uint8_t>iv;
    CBC_mode(std::vector<uint8_t> _key, std::vector<uint8_t> _iv);
    std::vector<uint8_t> cbc_encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> cbc_decrypt(const std::vector<uint8_t>& ciphertext);
    std::vector<uint8_t> pkcs7_padding(const std::vector<uint8_t>& data);
    std::vector<uint8_t> pkcs7_unpadding(const std::vector<uint8_t>& data);
};

#endif  // CBC_MODE_H
