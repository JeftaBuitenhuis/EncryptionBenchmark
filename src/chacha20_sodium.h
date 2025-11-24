#ifndef CHACHA20_SODIUM_H
#define CHACHA20_SODIUM_H

#include <cstdint>
#include <cstddef>
#include <vector>

class ChaCha20Sodium {
public:
    ChaCha20Sodium(const uint8_t key[32], const uint8_t nonce[12]);

    // Encrypt/decrypt in-place
    void encrypt_inplace(std::vector<uint8_t>& buffer);

private:
    uint8_t key_[32];
    uint8_t nonce_[12];
};

#endif // CHACHA20_SODIUM_H
