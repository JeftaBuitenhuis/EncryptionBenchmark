#ifndef CHACHA20_H
#define CHACHA20_H

#include <cstdint>
#include <cstddef>

class ChaCha20 {
public:
    ChaCha20(const uint8_t key[32], const uint8_t nonce[12]);

    // Encrypt/decrypt in-place
    void encrypt(uint8_t* data, size_t length);

private:
    void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    void chacha_block(uint32_t output[16]);

    uint32_t state[16];
    uint32_t counter;
};

#endif // CHACHA20_H
