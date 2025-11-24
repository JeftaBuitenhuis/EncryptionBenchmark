#include "aes_sodium.h"
#include <sodium.h>
#include <cstring>
#include <stdexcept>

AES_Sodium::AES_Sodium(const uint8_t key[32]) {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }
    std::memcpy(key_, key, 32);
}

void AES_Sodium::encrypt_inplace(std::vector<uint8_t>& buffer, const uint8_t nonce[16]) {
    if (buffer.empty()) return;

    // Allocate temporary ciphertext buffer
    std::vector<uint8_t> ciphertext(buffer.size());

    // AES-256 in CTR mode using libsodium's crypto_stream_chacha20 as a stand-in
    crypto_stream_xchacha20_xor(
        ciphertext.data(),        // output
        buffer.data(),            // input
        buffer.size(),            // length
        nonce,                    // nonce
        key_                      // key
    );

    // Copy encrypted data back
    std::memcpy(buffer.data(), ciphertext.data(), buffer.size());
}
