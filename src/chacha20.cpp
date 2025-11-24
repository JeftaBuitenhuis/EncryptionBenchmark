#include "chacha20.h"
#include <cstring>

ChaCha20::ChaCha20(const uint8_t key[32], const uint8_t nonce[12]) : counter(0) {
    // Constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646E;
    state[2] = 0x79622D32;
    state[3] = 0x6B206574;

    // Key
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = ((uint32_t)key[i*4 + 0]      ) |
                       ((uint32_t)key[i*4 + 1] << 8 ) |
                       ((uint32_t)key[i*4 + 2] << 16) |
                       ((uint32_t)key[i*4 + 3] << 24);
    }

    // Counter
    state[12] = counter;

    // Nonce
    state[13] = ((uint32_t)nonce[0]      ) |
                ((uint32_t)nonce[1] << 8 ) |
                ((uint32_t)nonce[2] << 16) |
                ((uint32_t)nonce[3] << 24);
    state[14] = ((uint32_t)nonce[4]      ) |
                ((uint32_t)nonce[5] << 8 ) |
                ((uint32_t)nonce[6] << 16) |
                ((uint32_t)nonce[7] << 24);
    state[15] = ((uint32_t)nonce[8]      ) |
                ((uint32_t)nonce[9] << 8 ) |
                ((uint32_t)nonce[10] << 16) |
                ((uint32_t)nonce[11] << 24);
}

void ChaCha20::quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8) | (d >> 24);
    c += d; b ^= c; b = (b << 7) | (b >> 25);
}

void ChaCha20::chacha_block(uint32_t output[16]) {
    std::memcpy(output, state, 64);
    for (int i = 0; i < 10; ++i) {
        // column rounds
        quarter_round(output[0], output[4], output[8], output[12]);
        quarter_round(output[1], output[5], output[9], output[13]);
        quarter_round(output[2], output[6], output[10], output[14]);
        quarter_round(output[3], output[7], output[11], output[15]);
        // diagonal rounds
        quarter_round(output[0], output[5], output[10], output[15]);
        quarter_round(output[1], output[6], output[11], output[12]);
        quarter_round(output[2], output[7], output[8], output[13]);
        quarter_round(output[3], output[4], output[9], output[14]);
    }
    for (int i = 0; i < 16; ++i) {
        output[i] += state[i];
    }
}

void ChaCha20::encrypt(uint8_t* data, size_t length) {
    uint32_t block[16];
    uint8_t keystream[64];

    while (length > 0) {
        state[12] = counter++;
        chacha_block(block);

        for (int i = 0; i < 16; ++i) {
            keystream[i*4 + 0] = (block[i]      ) & 0xFF;
            keystream[i*4 + 1] = (block[i] >> 8 ) & 0xFF;
            keystream[i*4 + 2] = (block[i] >> 16) & 0xFF;
            keystream[i*4 + 3] = (block[i] >> 24) & 0xFF;
        }

        size_t n = (length < 64) ? length : 64;
        for (size_t i = 0; i < n; ++i)
            data[i] ^= keystream[i];

        data += n;
        length -= n;
    }
}
