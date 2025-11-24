#ifndef CHACHA20_H
#define CHACHA20_H

#include <cstdint>
#include <cstddef>
#include <vector>

class ChaCha20 {
public:
    ChaCha20(const uint8_t key[32], const uint8_t nonce[12]);
    void encrypt_inplace(std::vector<uint8_t>& buffer);

private:
    uint8_t key_[32];
    uint8_t nonce_[12];
    uint32_t state[16];
    uint32_t counter;

    void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    void chacha_block(uint32_t output[16]);
    void encrypt(uint8_t* data, size_t length); // internal pointer-based function
};

#endif // CHACHA20_H
