#include <iostream>
#include <cstdint>
#include <vector>
#include <random>
#include <chrono>

#if defined(_MSC_VER)
    #include <intrin.h>
    unsigned long long rdtsc() { return __rdtsc(); }
#elif defined(__GNUC__)
    #include <x86intrin.h>
    unsigned long long rdtsc() { return __rdtsc(); }
#else
    #error "rdtsc not supported on this compiler"
#endif

extern "C" {
#include "aes.h"
}
#include "chacha20.h"
#include "chacha20poly1305.h"
#include "chacha20_sodium.h"
#include "aes_sodium.h"

void benchmark_aes(std::vector<uint8_t>& buffer, const uint8_t key[16]) {
    AES_ctx ctx;
    AES_init_ctx(&ctx, key);

    unsigned long long start = rdtsc();
    for (size_t i = 0; i < buffer.size(); i += AES_BLOCKLEN) {
        AES_ECB_encrypt(&ctx, buffer.data() + i);
    }
    unsigned long long end = rdtsc();

    size_t bytes = buffer.size();
    std::cout << "AES cycles total: " << (end - start) << "\n";
    std::cout << "AES cycles per byte: " << double(end - start) / bytes << "\n";
}

void benchmark_chacha20(std::vector<uint8_t>& buffer, const uint8_t key[32], const uint8_t nonce[12]) {
    ChaCha20 ctx(key, nonce);

    unsigned long long start = rdtsc();
    ctx.encrypt_inplace(buffer);
    unsigned long long end = rdtsc();

    size_t bytes = buffer.size();
    std::cout << "ChaCha20 cycles total: " << (end - start) << "\n";
    std::cout << "ChaCha20 cycles per byte: " << double(end - start) / bytes << "\n";
}

void benchmark_chacha20_poly1305(std::vector<uint8_t>& buffer,
                                 const uint8_t key[32],
                                 const uint8_t nonce[12]) {
    ChaCha20Poly1305 ctx(key, nonce);

    unsigned long long start = rdtsc();
    ctx.encrypt_inplace(buffer);  // measures actual AEAD encryption
    unsigned long long end = rdtsc();

    size_t bytes = buffer.size() - 16; // exclude tag
    std::cout << "ChaCha20Poly1305 cycles total: " << (end - start) << "\n";
    std::cout << "ChaCha20Poly1305 cycles per byte: " << double(end - start) / bytes << "\n";
}

void benchmark_chacha20_sodium(std::vector<uint8_t>& buffer, const uint8_t key[32], const uint8_t nonce[12]) {
    ChaCha20Sodium ctx(key, nonce);

    unsigned long long start = rdtsc();
    ctx.encrypt_inplace(buffer);
    unsigned long long end = rdtsc();

    size_t bytes = buffer.size();
    std::cout << "ChaCha20 Sodium cycles total: " << (end - start) << "\n";
    std::cout << "ChaCha20 Sodium cycles per byte: " << double(end - start) / bytes << "\n";
}

void benchmark_aes_sodium(std::vector<uint8_t>& buffer, const uint8_t key[32], const uint8_t nonce[16]) {
    AES_Sodium ctx(key);

    unsigned long long start = rdtsc();
    ctx.encrypt_inplace(buffer, nonce);
    unsigned long long end = rdtsc();

    size_t bytes = buffer.size();
    std::cout << "AES-Sodium cycles total: " << (end - start) << "\n";
    std::cout << "AES-Sodium cycles per byte: " << double(end - start) / bytes << "\n";
}

int main() {
    const size_t BUFFER_SIZE = 1024 * 1024 * 32; // 32 MB buffer
    std::vector<uint8_t> buffer(BUFFER_SIZE);

    std::random_device rd;
    for (auto &b : buffer) b = rd() % 256;

    uint8_t aes_key[16] = {0};
    uint8_t chacha_key[32] = {0};
    uint8_t chacha_nonce[12] = {0};

    benchmark_aes(buffer, aes_key);

    // refill buffer for fair comparison
    for (auto &b : buffer) b = rd() % 256;

    benchmark_aes_sodium(buffer, chacha_key, chacha_nonce);

    // refill buffer for fair comparison
    for (auto &b : buffer) b = rd() % 256;

    benchmark_chacha20(buffer, chacha_key, chacha_nonce);

    // refill buffer for fair comparison
    for (auto &b : buffer) b = rd() % 256;

    benchmark_chacha20_sodium(buffer, chacha_key, chacha_nonce);

    // refill buffer for fair comparison
    for (auto &b : buffer) b = rd() % 256;

    benchmark_chacha20_poly1305(buffer, chacha_key, chacha_nonce);

    return 0;
}
