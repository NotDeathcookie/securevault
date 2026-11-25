// OpenSSL EVP backend for vault_crypto.hpp - used on Linux and macOS.
#include "vault_crypto.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace vault {

static std::string OpenSSLError() {
    char buf[256];
    unsigned long e = ERR_get_error();
    ERR_error_string_n(e, buf, sizeof(buf));
    return buf[0] ? std::string(buf) : "unknown OpenSSL error";
}

std::string HashAlgoName(HashAlgo a) {
    switch (a) {
        case HashAlgo::SHA256: return "sha256";
        case HashAlgo::SHA512: return "sha512";
        case HashAlgo::SHA384: return "sha384";
        case HashAlgo::SHA1:   return "sha1";
        case HashAlgo::MD5:    return "md5";
    }
    return "sha256";
}

std::vector<uint8_t> RandomBytes(size_t n) {
    std::vector<uint8_t> buf(n);
    if (RAND_bytes(buf.data(), (int)n) != 1)
        throw std::runtime_error("RNG failure: " + OpenSSLError());
    return buf;
}

std::array<uint8_t, kKeyLen> DeriveKey(const std::vector<uint8_t>& secret,
                                        const uint8_t* salt, size_t salt_len) {
    std::array<uint8_t, kKeyLen> key{};
    int rc = PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(secret.data()),
                                (int)secret.size(), salt, (int)salt_len,
                                kPbkdf2Iterations, EVP_sha256(), (int)kKeyLen,
                                key.data());
    if (rc != 1) throw std::runtime_error("Key derivation failed: " + OpenSSLError());
    return key;
}

std::vector<uint8_t> AesGcmEncrypt(const std::array<uint8_t, kKeyLen>& key,
                                    const uint8_t* nonce,
                                    const uint8_t* plaintext, size_t len,
                                    const uint8_t* aad, size_t aad_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::vector<uint8_t> out(len + kTagLen);
    int outl = 0, tmp = 0;
    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("EncryptInit failed");
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)kNonceLen, nullptr) != 1)
            throw std::runtime_error("Set IV len failed");
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1)
            throw std::runtime_error("EncryptInit (key/iv) failed");
        if (aad_len > 0 &&
            EVP_EncryptUpdate(ctx, nullptr, &tmp, aad, (int)aad_len) != 1)
            throw std::runtime_error("AAD update failed");
        if (len > 0) {
            if (EVP_EncryptUpdate(ctx, out.data(), &outl, plaintext, (int)len) != 1)
                throw std::runtime_error("EncryptUpdate failed");
        }
        if (EVP_EncryptFinal_ex(ctx, out.data() + outl, &tmp) != 1)
            throw std::runtime_error("EncryptFinal failed");
        outl += tmp;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)kTagLen, out.data() + outl) != 1)
            throw std::runtime_error("Get tag failed");
        outl += (int)kTagLen;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);
    out.resize(outl);
    return out;
}

std::vector<uint8_t> AesGcmDecrypt(const std::array<uint8_t, kKeyLen>& key,
                                    const uint8_t* nonce,
                                    const uint8_t* ciphertext_and_tag, size_t len,
                                    const uint8_t* aad, size_t aad_len) {
    if (len < kTagLen) throw std::runtime_error("Ciphertext too short");
    size_t ct_len = len - kTagLen;
    const uint8_t* tag = ciphertext_and_tag + ct_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::vector<uint8_t> out(ct_len);
    int outl = 0, tmp = 0;
    bool authOk = false;
    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("DecryptInit failed");
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)kNonceLen, nullptr) != 1)
            throw std::runtime_error("Set IV len failed");
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1)
            throw std::runtime_error("DecryptInit (key/iv) failed");
        if (aad_len > 0 &&
            EVP_DecryptUpdate(ctx, nullptr, &tmp, aad, (int)aad_len) != 1)
            throw std::runtime_error("AAD update failed");
        if (ct_len > 0) {
            if (EVP_DecryptUpdate(ctx, out.data(), &outl, ciphertext_and_tag, (int)ct_len) != 1)
                throw std::runtime_error("DecryptUpdate failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)kTagLen, (void*)tag) != 1)
            throw std::runtime_error("Set tag failed");
        authOk = (EVP_DecryptFinal_ex(ctx, out.data() + outl, &tmp) == 1);
        outl += tmp;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!authOk)
        throw std::runtime_error(
            "Decryption failed: incorrect password/key file, or the data was modified.");
    out.resize(outl);
    return out;
}

struct Hasher::Impl {
    EVP_MD_CTX* ctx = nullptr;
};

static const EVP_MD* MdFor(HashAlgo a) {
    switch (a) {
        case HashAlgo::SHA256: return EVP_sha256();
        case HashAlgo::SHA512: return EVP_sha512();
        case HashAlgo::SHA384: return EVP_sha384();
        case HashAlgo::SHA1:   return EVP_sha1();
        case HashAlgo::MD5:    return EVP_md5();
    }
    return EVP_sha256();
}

Hasher::Hasher(HashAlgo algo) : impl_(new Impl) {
    impl_->ctx = EVP_MD_CTX_new();
    if (!impl_->ctx || EVP_DigestInit_ex(impl_->ctx, MdFor(algo), nullptr) != 1)
        throw std::runtime_error("Could not initialize digest.");
}
Hasher::~Hasher() {
    if (impl_ && impl_->ctx) EVP_MD_CTX_free(impl_->ctx);
}
void Hasher::Update(const uint8_t* data, size_t len) {
    EVP_DigestUpdate(impl_->ctx, data, len);
}
std::string Hasher::FinalizeHex() {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_DigestFinal_ex(impl_->ctx, digest, &digest_len);
    std::ostringstream oss;
    for (unsigned int i = 0; i < digest_len; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    return oss.str();
}

}  // namespace vault
