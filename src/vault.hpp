// vault.hpp
// Core vault logic ported from secure_vault-wy-hash.py: text/file/folder
// AES-256-GCM encryption, PBKDF2-HMAC-SHA256 key derivation, chunked file
// handling, multi-algorithm hashing, and multi-pass secure shredding.
//
// The actual crypto primitives (AES-GCM, PBKDF2, hashing, RNG) come from
// vault_crypto.hpp, which has a Linux/macOS (OpenSSL) backend and a Windows
// (CNG/bcrypt) backend - see vault_crypto_openssl.cpp / vault_crypto_win.cpp.
// Everything in *this* file is platform-independent.
//
// All heavy work (file I/O, encryption, shredding) runs on a background
// std::thread so the ImGui frame loop never blocks. Progress is reported
// through std::atomic<float> fields on VaultJob that the UI polls each frame.

#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

#include "vault_crypto.hpp"

namespace fs = std::filesystem;

namespace vault {

constexpr size_t kChunkSize = 64 * 1024;  // 64 KB, matches Python CHUNK_SIZE

// ---- Text payload: base64( salt(16) || nonce(12) || ciphertext+tag ) ------
// Same layout as Python's encrypt_data()/decrypt_data().
std::string EncryptText(const std::vector<uint8_t>& secret, const std::string& plaintext);
std::string DecryptText(const std::vector<uint8_t>& secret, const std::string& payload_b64);

std::string Base64Encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> Base64Decode(const std::string& text);

// ---- Job: a single long running operation driven from a background thread -

enum class JobKind {
    None, EncryptText, DecryptText, EncryptFile, DecryptFile,
    EncryptFolder, DecryptFolder, HashFile, Shred
};

struct VaultJob {
    std::atomic<bool>  running{false};
    std::atomic<bool>  done{false};
    std::atomic<bool>  ok{false};
    std::atomic<float> progress{0.0f};     // 0..1
    std::mutex         result_mutex;
    std::string        result_text;        // human readable result / error
    std::string        output_path;        // where output landed, if any
    JobKind            kind = JobKind::None;

    void SetResult(bool success, const std::string& text, const std::string& out_path = "") {
        std::lock_guard<std::mutex> lk(result_mutex);
        ok = success;
        result_text = text;
        output_path = out_path;
        done = true;
        running = false;
    }
};

// File encryption: salt(16) header, then repeated [u32 be length][nonce(12)+ciphertext+tag]
// chunks - identical container format to the Python version so files produced
// by either implementation can be decrypted by the other (and so the Linux
// and Windows builds of this app can decrypt each other's files too).
void EncryptFile(const std::vector<uint8_t>& secret, const fs::path& in, const fs::path& out,
                  VaultJob& job);
void DecryptFile(const std::vector<uint8_t>& secret, const fs::path& in, const fs::path& out,
                  VaultJob& job);

// Folder archive: a minimal custom container (relative path + size + bytes for
// every file, recursively) is streamed into a temp file, then run through
// EncryptFile/DecryptFile. This plays the same role as Python's zipfile step
// without requiring an external zip library.
void EncryptFolder(const std::vector<uint8_t>& secret, const fs::path& folder,
                    const fs::path& out, VaultJob& job);
void DecryptFolder(const std::vector<uint8_t>& secret, const fs::path& archive,
                    const fs::path& out_folder, VaultJob& job);

// What can be learned about an encrypted file WITHOUT the password: its format
// and whether its structure is complete. Cannot tell if the data is genuine.
struct FileInfo {
    bool readable = false;      // file could be opened and recognised
    int version = 0;            // 2 = current format, 1 = legacy, 0 = unknown
    uint64_t file_size = 0;
    uint64_t chunks = 0;
    uint32_t chunk_size = 0;    // v2 only
    bool structure_ok = false;  // every length is sane, exactly one final chunk, no trailing bytes
    std::string summary;        // human readable report
};
FileInfo InspectFile(const fs::path& path);

// Decrypts the whole file in memory-sized pieces and checks every chunk's
// authentication tag, without writing anything. Result goes to job.SetResult().
void VerifyFile(const std::vector<uint8_t>& secret, const fs::path& path, VaultJob& job);

std::string HashFile(const fs::path& path, HashAlgo algo, VaultJob& job);

// Overwrites file contents with random bytes for `passes` passes, fsyncs,
// then deletes it - matches Python's shred_file()/shred_folder().
void ShredFile(const fs::path& path, int passes, VaultJob& job);
void ShredPath(const fs::path& path, int passes, VaultJob& job);

}  // namespace vault
