#include "chacha20_sodium.h"
#include <sodium.h>
#include <cstring>

ChaCha20Sodium::ChaCha20Sodium(const uint8_t key[32], const uint8_t nonce[12]) {
    std::memcpy(key_, key, 32);
    std::memcpy(nonce_, nonce, 12);
}

void ChaCha20Sodium::encrypt_inplace(std::vector<uint8_t>& buffer) {
    crypto_stream_chacha20_ietf_xor(buffer.data(), buffer.data(), buffer.size(), nonce_, key_);
}
