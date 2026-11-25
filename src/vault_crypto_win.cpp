// Windows backend for vault_crypto.hpp, using CNG (bcrypt.h) - part of
// Windows itself since Vista/Server 2008, so no external crypto library
// (OpenSSL etc.) needs to be bundled or cross-compiled for the Windows build.
// Link with -lbcrypt (CMakeLists.txt does this automatically on Windows).
#include "vault_crypto.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

namespace vault {

static std::string NtStatusMsg(const char* what, NTSTATUS st) {
    std::ostringstream oss;
    oss << what << " (NTSTATUS 0x" << std::hex << (unsigned long)st << ")";
    return oss.str();
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
    NTSTATUS st = BCryptGenRandom(nullptr, buf.data(), (ULONG)n,
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) throw std::runtime_error(NtStatusMsg("RNG failure", st));
    return buf;
}

// Small RAII wrapper so every early-throw path still closes its handle.
struct AlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};
struct KeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() { if (h) BCryptDestroyKey(h); }
};

std::array<uint8_t, kKeyLen> DeriveKey(const std::vector<uint8_t>& secret,
                                        const uint8_t* salt, size_t salt_len) {
    AlgHandle alg;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_SHA256_ALGORITHM, nullptr,
                                               BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st != 0) throw std::runtime_error(NtStatusMsg("Open PBKDF2 PRF failed", st));

    std::array<uint8_t, kKeyLen> key{};
    st = BCryptDeriveKeyPBKDF2(alg.h, const_cast<PUCHAR>(secret.data()), (ULONG)secret.size(),
                                const_cast<PUCHAR>(salt), (ULONG)salt_len,
                                (ULONGLONG)kPbkdf2Iterations, key.data(), (ULONG)kKeyLen, 0);
    if (st != 0) throw std::runtime_error(NtStatusMsg("Key derivation failed", st));
    return key;
}

static KeyHandle MakeAesKey(const std::array<uint8_t, kKeyLen>& key) {
    AlgHandle alg;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (st != 0) throw std::runtime_error(NtStatusMsg("Open AES provider failed", st));
    st = BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                            sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st != 0) throw std::runtime_error(NtStatusMsg("Set GCM mode failed", st));

    KeyHandle keyH;
    st = BCryptGenerateSymmetricKey(alg.h, &keyH.h, nullptr, 0,
                                     const_cast<PUCHAR>(key.data()), (ULONG)key.size(), 0);
    if (st != 0) throw std::runtime_error(NtStatusMsg("Generate AES key failed", st));
    return keyH;
}

std::vector<uint8_t> AesGcmEncrypt(const std::array<uint8_t, kKeyLen>& key,
                                    const uint8_t* nonce,
                                    const uint8_t* plaintext, size_t len) {
    KeyHandle keyH = MakeAesKey(key);

    std::vector<uint8_t> out(len + kTagLen);
    uint8_t tag[kTagLen];

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = (ULONG)kNonceLen;
    info.pbTag = tag;
    info.cbTag = (ULONG)kTagLen;

    ULONG result_len = 0;
    NTSTATUS st = BCryptEncrypt(keyH.h, const_cast<PUCHAR>(plaintext), (ULONG)len, &info,
                                 nullptr, 0, out.data(), (ULONG)len, &result_len, 0);
    if (st != 0) throw std::runtime_error(NtStatusMsg("AES-GCM encrypt failed", st));

    std::memcpy(out.data() + len, tag, kTagLen);
    out.resize(len + kTagLen);
    return out;
}

std::vector<uint8_t> AesGcmDecrypt(const std::array<uint8_t, kKeyLen>& key,
                                    const uint8_t* nonce,
                                    const uint8_t* ciphertext_and_tag, size_t len) {
    if (len < kTagLen) throw std::runtime_error("Ciphertext too short");
    size_t ct_len = len - kTagLen;
    uint8_t tag[kTagLen];
    std::memcpy(tag, ciphertext_and_tag + ct_len, kTagLen);

    KeyHandle keyH = MakeAesKey(key);

    std::vector<uint8_t> out(ct_len);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = (ULONG)kNonceLen;
    info.pbTag = tag;
    info.cbTag = (ULONG)kTagLen;

    ULONG result_len = 0;
    NTSTATUS st = BCryptDecrypt(keyH.h, const_cast<PUCHAR>(ciphertext_and_tag), (ULONG)ct_len,
                                 &info, nullptr, 0, ct_len ? out.data() : nullptr, (ULONG)ct_len,
                                 &result_len, 0);
    if (st != 0) {
        // STATUS_AUTH_TAG_MISMATCH and any other failure both mean "reject".
        throw std::runtime_error(
            "Decryption failed: incorrect password/key file, or the data was modified.");
    }
    out.resize(result_len);
    return out;
}

static LPCWSTR AlgIdFor(HashAlgo a) {
    switch (a) {
        case HashAlgo::SHA256: return BCRYPT_SHA256_ALGORITHM;
        case HashAlgo::SHA512: return BCRYPT_SHA512_ALGORITHM;
        case HashAlgo::SHA384: return BCRYPT_SHA384_ALGORITHM;
        case HashAlgo::SHA1:   return BCRYPT_SHA1_ALGORITHM;
        case HashAlgo::MD5:    return BCRYPT_MD5_ALGORITHM;
    }
    return BCRYPT_SHA256_ALGORITHM;
}

struct Hasher::Impl {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<uint8_t> object_buf;
};

Hasher::Hasher(HashAlgo algo) : impl_(new Impl) {
    NTSTATUS st = BCryptOpenAlgorithmProvider(&impl_->alg, AlgIdFor(algo), nullptr, 0);
    if (st != 0) throw std::runtime_error(NtStatusMsg("Open hash provider failed", st));

    DWORD object_len = 0, cbData = 0;
    BCryptGetProperty(impl_->alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_len, sizeof(DWORD),
                       &cbData, 0);
    impl_->object_buf.resize(object_len ? object_len : 256);

    st = BCryptCreateHash(impl_->alg, &impl_->hash, impl_->object_buf.data(),
                           (ULONG)impl_->object_buf.size(), nullptr, 0, 0);
    if (st != 0) throw std::runtime_error(NtStatusMsg("Create hash failed", st));
}
Hasher::~Hasher() {
    if (impl_) {
        if (impl_->hash) BCryptDestroyHash(impl_->hash);
        if (impl_->alg) BCryptCloseAlgorithmProvider(impl_->alg, 0);
    }
}
void Hasher::Update(const uint8_t* data, size_t len) {
    BCryptHashData(impl_->hash, const_cast<PUCHAR>(data), (ULONG)len, 0);
}
std::string Hasher::FinalizeHex() {
    DWORD hash_len = 0, cbData = 0;
    BCryptGetProperty(impl_->alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(DWORD), &cbData, 0);
    std::vector<uint8_t> digest(hash_len);
    BCryptFinishHash(impl_->hash, digest.data(), hash_len, 0);

    std::ostringstream oss;
    for (uint8_t b : digest)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

}  // namespace vault
