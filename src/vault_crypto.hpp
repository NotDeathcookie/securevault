// vault_crypto.hpp
// Platform crypto primitives used by vault.cpp. Two backends implement this
// interface:
//   vault_crypto_openssl.cpp  - Linux / macOS, via OpenSSL EVP
//   vault_crypto_win.cpp      - Windows, via CNG (bcrypt.h) - no OpenSSL
//                                dependency needed on Windows at all.
// Exactly one backend is compiled in (selected in CMakeLists.txt by platform).
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace vault {

constexpr size_t kSaltLen  = 16;
constexpr size_t kNonceLen = 12;
constexpr size_t kKeyLen   = 32;  // AES-256
constexpr size_t kTagLen   = 16;  // AES-GCM auth tag
constexpr uint32_t kPbkdf2Iterations = 600000;

enum class HashAlgo { SHA256, SHA512, SHA384, SHA1, MD5 };
std::string HashAlgoName(HashAlgo a);

std::vector<uint8_t> RandomBytes(size_t n);

std::array<uint8_t, kKeyLen> DeriveKey(const std::vector<uint8_t>& secret,
                                        const uint8_t* salt, size_t salt_len);

// Throws std::runtime_error on failure (bad tag on decrypt == wrong
// password/key or tampered data).
// `aad` is additional authenticated data: not encrypted, but covered by the
// tag, so changing it makes decryption fail.
std::vector<uint8_t> AesGcmEncrypt(const std::array<uint8_t, kKeyLen>& key,
                                    const uint8_t* nonce,
                                    const uint8_t* plaintext, size_t len,
                                    const uint8_t* aad = nullptr, size_t aad_len = 0);
std::vector<uint8_t> AesGcmDecrypt(const std::array<uint8_t, kKeyLen>& key,
                                    const uint8_t* nonce,
                                    const uint8_t* ciphertext_and_tag, size_t len,
                                    const uint8_t* aad = nullptr, size_t aad_len = 0);

// Streaming digest, used by HashFile() to hash large files in chunks.
class Hasher {
public:
    explicit Hasher(HashAlgo algo);
    ~Hasher();
    Hasher(const Hasher&) = delete;
    Hasher& operator=(const Hasher&) = delete;

    void Update(const uint8_t* data, size_t len);
    std::string FinalizeHex();  // lowercase hex digest

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace vault
