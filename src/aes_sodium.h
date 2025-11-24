#ifndef AES_SODIUM_H
#define AES_SODIUM_H

#include <cstdint>
#include <vector>

class AES_Sodium {
public:
    explicit AES_Sodium(const uint8_t key[32]);

    // Encrypt/decrypt in-place using AES-256 in stream mode (via libsodium)
    void encrypt_inplace(std::vector<uint8_t>& buffer, const uint8_t nonce[16]);

private:
    uint8_t key_[32];
};

#endif // AES_SODIUM_H
