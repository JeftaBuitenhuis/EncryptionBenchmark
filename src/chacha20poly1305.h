#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <cstdint>
#include <cstddef>
#include <vector>

class ChaCha20Poly1305 {
public:
    ChaCha20Poly1305(const uint8_t key[32], const uint8_t nonce[12]);

    // In-place wrapper: encrypts buffer and appends AEAD tag
    void encrypt_inplace(std::vector<uint8_t>& buffer);

    // Full AEAD encryption: outputs ciphertext + tag
    void encrypt(
        const uint8_t* plaintext,
        size_t plaintext_len,
        const uint8_t* ad,
        size_t ad_len,
        std::vector<uint8_t>& ciphertext,
        std::vector<uint8_t>& tag
    );

private:
    uint8_t key_[32];
    uint8_t nonce_[12];
};

#endif // CHACHA20POLY1305_H
