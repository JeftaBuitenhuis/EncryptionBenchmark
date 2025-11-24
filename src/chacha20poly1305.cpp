#include "chacha20poly1305.h"
#include <sodium.h>
#include <stdexcept>
#include <cstring>

ChaCha20Poly1305::ChaCha20Poly1305(const uint8_t key[32], const uint8_t nonce[12]) {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium init failed");
    }
    std::memcpy(key_, key, 32);
    std::memcpy(nonce_, nonce, 12);
}

// Full AEAD encryption
void ChaCha20Poly1305::encrypt(
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* ad,
    size_t ad_len,
    std::vector<uint8_t>& ciphertext,
    std::vector<uint8_t>& tag
) {
    ciphertext.resize(plaintext_len + crypto_aead_chacha20poly1305_ietf_ABYTES);
    tag.resize(crypto_aead_chacha20poly1305_ietf_ABYTES);

    unsigned long long clen;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &clen,
        plaintext, plaintext_len,
        ad, ad_len,
        nullptr,  // nsec
        nonce_, key_
    );

    ciphertext.resize(clen);
    std::memcpy(tag.data(), ciphertext.data() + plaintext_len, crypto_aead_chacha20poly1305_ietf_ABYTES);
}

// In-place wrapper for benchmarking
void ChaCha20Poly1305::encrypt_inplace(std::vector<uint8_t>& buffer) {
    std::vector<uint8_t> ciphertext, tag;
    encrypt(buffer.data(), buffer.size(), nullptr, 0, ciphertext, tag);

    // Resize buffer to hold ciphertext + tag for in-place AEAD
    buffer.resize(ciphertext.size());
    std::memcpy(buffer.data(), ciphertext.data(), ciphertext.size());
}
