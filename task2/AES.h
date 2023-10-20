#ifndef AES_H
#define AES_H

#include <vector>
#include <cstdlib>
#include <cstdint>

class AES {
public:
    std::vector<uint8_t> key;
    int key_length;
    AES(const std::vector<uint8_t>& key, int key_length);
    std::vector<std::vector<uint8_t>> round_keys;
    static const std::vector<uint8_t> S_BOX;
    static const std::vector<std::vector<uint8_t>> RCON;
    static const std::vector<uint8_t> INV_S_BOX;
    std::vector<std::vector<uint8_t>> key_expansion_128();
    std::vector<std::vector<uint8_t>> key_expansion_192();
    std::vector<std::vector<uint8_t>> key_expansion_256();
    //std::vector<uint8_t> sub_word(const std::vector<uint8_t>& word);
    //std::vector<uint8_t> rot_word(const std::vector<uint8_t>& word);
    std::vector<std::vector<uint8_t>> key_expansion();
    void add_round_key(std::vector<std::vector<uint8_t>>& state, int round);
    void inv_sub_bytes(std::vector<std::vector<uint8_t>>& state);
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);
};

#endif