#include "vault.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>

#if defined(_WIN32)
  #include <process.h>  // _getpid
  #define VAULT_GETPID() _getpid()
#else
  #include <unistd.h>   // getpid
  #define VAULT_GETPID() ::getpid()
#endif

namespace vault {

// ---- base64 -----------------------------------------------------------

static const char kB64Table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const std::vector<uint8_t>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= data.size()) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += kB64Table[(n >> 18) & 0x3F];
        out += kB64Table[(n >> 12) & 0x3F];
        out += kB64Table[(n >> 6) & 0x3F];
        out += kB64Table[n & 0x3F];
        i += 3;
    }
    size_t rem = data.size() - i;
    if (rem == 1) {
        uint32_t n = data[i] << 16;
        out += kB64Table[(n >> 18) & 0x3F];
        out += kB64Table[(n >> 12) & 0x3F];
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
        out += kB64Table[(n >> 18) & 0x3F];
        out += kB64Table[(n >> 12) & 0x3F];
        out += kB64Table[(n >> 6) & 0x3F];
        out += '=';
    }
    return out;
}

static int B64Val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::vector<uint8_t> Base64Decode(const std::string& text) {
    std::vector<uint8_t> out;
    out.reserve((text.size() / 4) * 3);
    int vals[4];
    size_t vi = 0;
    for (char c : text) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        int v = B64Val(c);
        if (v < 0) continue;
        vals[vi++] = v;
        if (vi == 4) {
            uint32_t n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
            out.push_back((n >> 16) & 0xFF);
            out.push_back((n >> 8) & 0xFF);
            out.push_back(n & 0xFF);
            vi = 0;
        }
    }
    if (vi >= 2) {
        uint32_t n = (vals[0] << 18) | (vals[1] << 12);
        out.push_back((n >> 16) & 0xFF);
        if (vi == 3) {
            n |= (vals[2] << 6);
            out.push_back((n >> 8) & 0xFF);
        }
    }
    return out;
}

// ---- text encryption ----------------------------------------------------

std::string EncryptText(const std::vector<uint8_t>& secret, const std::string& plaintext) {
    auto salt = RandomBytes(kSaltLen);
    auto key = DeriveKey(secret, salt.data(), salt.size());
    auto nonce = RandomBytes(kNonceLen);
    auto ct = AesGcmEncrypt(key, nonce.data(),
                             reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    std::vector<uint8_t> payload;
    payload.reserve(salt.size() + nonce.size() + ct.size());
    payload.insert(payload.end(), salt.begin(), salt.end());
    payload.insert(payload.end(), nonce.begin(), nonce.end());
    payload.insert(payload.end(), ct.begin(), ct.end());
    return Base64Encode(payload);
}

std::string DecryptText(const std::vector<uint8_t>& secret, const std::string& payload_b64) {
    auto payload = Base64Decode(payload_b64);
    if (payload.size() < kSaltLen + kNonceLen + kTagLen)
        throw std::runtime_error("Malformed payload (too short).");
    const uint8_t* salt = payload.data();
    const uint8_t* nonce = payload.data() + kSaltLen;
    const uint8_t* ct = payload.data() + kSaltLen + kNonceLen;
    size_t ct_len = payload.size() - kSaltLen - kNonceLen;

    auto key = DeriveKey(secret, salt, kSaltLen);
    auto pt = AesGcmDecrypt(key, nonce, ct, ct_len);
    return std::string(pt.begin(), pt.end());
}

// ---- file encryption ------------------------------------------------------
//
// Container format v2
//   header (25 bytes): "SVLT" | version (0x02) | chunk_size u32 BE | salt (16)
//   then one or more chunks:
//     u32 BE  word = (final_flag << 31) | ciphertext_len   (ciphertext incl. 16-byte tag)
//     bytes   AES-256-GCM ciphertext + tag
//
//   key    = PBKDF2-HMAC-SHA256(secret, salt)       (unique per file: random salt)
//   nonce  = 4 zero bytes | chunk_index u64 BE      (counter; key is never reused across files)
//   AAD    = header | final_flag byte
//
// Because the nonce encodes the chunk index, moving or duplicating a chunk makes
// its tag fail. Because every chunk's AAD carries the final flag and the reader
// requires exactly one final chunk at the very end, cutting chunks off the end
// (or appending data) is detected. The header is authenticated by every chunk.
//
// Legacy v1 files (salt | [u32 len][nonce | ct+tag]...) are still readable.

static const uint8_t kMagic[4] = {'S', 'V', 'L', 'T'};
constexpr uint8_t  kFormatVersion = 2;
constexpr size_t   kHeaderLen = 4 + 1 + 4 + kSaltLen;  // 25
constexpr uint32_t kMaxChunkSize = 16u * 1024 * 1024;

static void MakeNonce(uint64_t counter, uint8_t nonce[kNonceLen]) {
    std::memset(nonce, 0, kNonceLen);
    for (int i = 0; i < 8; i++) nonce[4 + i] = uint8_t(counter >> (8 * (7 - i)));
}

static std::vector<uint8_t> BuildAad(const uint8_t* header, bool final_chunk) {
    std::vector<uint8_t> aad(header, header + kHeaderLen);
    aad.push_back(final_chunk ? 1 : 0);
    return aad;
}

static void PutU32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}
static uint32_t GetU32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

void EncryptFile(const std::vector<uint8_t>& secret, const fs::path& in, const fs::path& out,
                  VaultJob& job) {
    std::error_code ec;
    uint64_t total_size = fs::file_size(in, ec);
    if (ec) { job.SetResult(false, "Could not stat input file: " + ec.message()); return; }

    // Write to a temp name and rename on success, so a failed run never leaves
    // a half-written file under the real name.
    fs::path tmp = out;
    tmp += ".part";

    std::ifstream fin(in, std::ios::binary);
    std::ofstream fout(tmp, std::ios::binary);
    if (!fin || !fout) { job.SetResult(false, "Could not open input/output file."); return; }

    try {
        auto salt = RandomBytes(kSaltLen);
        uint8_t header[kHeaderLen];
        std::memcpy(header, kMagic, 4);
        header[4] = kFormatVersion;
        PutU32(header + 5, (uint32_t)kChunkSize);
        std::memcpy(header + 9, salt.data(), kSaltLen);

        auto key = DeriveKey(secret, salt.data(), salt.size());
        fout.write(reinterpret_cast<const char*>(header), kHeaderLen);

        std::vector<uint8_t> chunk(kChunkSize);
        uint64_t counter = 0, processed = 0;
        bool final_chunk = false;
        while (!final_chunk) {
            fin.read(reinterpret_cast<char*>(chunk.data()), (std::streamsize)kChunkSize);
            size_t got = (size_t)fin.gcount();
            if (fin.bad()) throw std::runtime_error("Read error on input file.");
            final_chunk = (fin.peek() == std::ifstream::traits_type::eof());

            uint8_t nonce[kNonceLen];
            MakeNonce(counter, nonce);
            auto aad = BuildAad(header, final_chunk);
            auto enc = AesGcmEncrypt(key, nonce, chunk.data(), got, aad.data(), aad.size());

            uint8_t word[4];
            PutU32(word, (uint32_t)enc.size() | (final_chunk ? 0x80000000u : 0u));
            fout.write(reinterpret_cast<const char*>(word), 4);
            fout.write(reinterpret_cast<const char*>(enc.data()), (std::streamsize)enc.size());

            counter++;
            processed += got;
            job.progress = total_size > 0 ? (float)((double)processed / (double)total_size) : 1.0f;
        }
        fout.flush();
        if (!fout) throw std::runtime_error("Write failed (disk full?).");
        fout.close();
        fin.close();

        fs::remove(out, ec);
        fs::rename(tmp, out);
        job.progress = 1.0f;
        job.SetResult(true, "File encrypted successfully.", out.string());
    } catch (const std::exception& e) {
        fout.close();
        std::error_code rm_ec;
        fs::remove(tmp, rm_ec);
        job.SetResult(false, std::string("Encryption failed: ") + e.what());
    }
}

// Reads and verifies a v2 stream (header already consumed into `header`).
static void DecryptStreamV2(const std::vector<uint8_t>& secret, std::ifstream& fin,
                             const uint8_t* header, uint64_t total_size, std::ofstream& fout,
                             VaultJob& job) {
    uint32_t chunk_size = GetU32(header + 5);
    if (chunk_size == 0 || chunk_size > kMaxChunkSize)
        throw std::runtime_error("Corrupted file header.");

    auto key = DeriveKey(secret, header + 9, kSaltLen);
    const size_t max_ct = (size_t)chunk_size + kTagLen;

    uint64_t counter = 0, processed = kHeaderLen;
    bool saw_final = false;
    while (true) {
        uint8_t word[4];
        fin.read(reinterpret_cast<char*>(word), 4);
        std::streamsize got = fin.gcount();
        if (got == 0) break;  // clean end of file
        if (got < 4) throw std::runtime_error("Corrupted file (truncated chunk header).");
        if (saw_final)
            throw std::runtime_error("Unexpected data after the final chunk - the file was modified.");

        uint32_t w = GetU32(word);
        bool final_chunk = (w & 0x80000000u) != 0;
        size_t ct_len = (size_t)(w & 0x7FFFFFFFu);
        if (ct_len < kTagLen || ct_len > max_ct)
            throw std::runtime_error("Corrupted file (bad chunk length).");
        if (!final_chunk && ct_len != max_ct)
            throw std::runtime_error("Corrupted file (short non-final chunk).");

        std::vector<uint8_t> ct(ct_len);
        fin.read(reinterpret_cast<char*>(ct.data()), (std::streamsize)ct_len);
        if ((size_t)fin.gcount() != ct_len)
            throw std::runtime_error("Corrupted file (truncated chunk).");

        uint8_t nonce[kNonceLen];
        MakeNonce(counter, nonce);
        auto aad = BuildAad(header, final_chunk);
        auto pt = AesGcmDecrypt(key, nonce, ct.data(), ct.size(), aad.data(), aad.size());
        fout.write(reinterpret_cast<const char*>(pt.data()), (std::streamsize)pt.size());

        saw_final = final_chunk;
        counter++;
        processed += 4 + ct_len;
        job.progress = total_size > 0
                            ? std::min(1.0f, (float)((double)processed / (double)total_size))
                            : 1.0f;
    }
    if (!saw_final)
        throw std::runtime_error("File is truncated (the final chunk is missing).");
}

// Legacy v1: salt | [u32 len][nonce | ct+tag] ... (no ordering/truncation protection).
static void DecryptStreamV1(const std::vector<uint8_t>& secret, std::ifstream& fin,
                             uint64_t total_size, std::ofstream& fout, VaultJob& job) {
    uint8_t salt[kSaltLen];
    fin.read(reinterpret_cast<char*>(salt), kSaltLen);
    if (fin.gcount() < (std::streamsize)kSaltLen)
        throw std::runtime_error("Corrupted file header (salt missing).");

    auto key = DeriveKey(secret, salt, kSaltLen);
    uint64_t processed = kSaltLen;
    while (fin) {
        uint8_t lenbuf[4];
        fin.read(reinterpret_cast<char*>(lenbuf), 4);
        std::streamsize got_len = fin.gcount();
        if (got_len == 0) break;
        if (got_len < 4) throw std::runtime_error("Corrupted file (truncated length).");

        uint32_t plen = GetU32(lenbuf);
        if (plen < kNonceLen + kTagLen || plen > (1u << 20))
            throw std::runtime_error("Corrupted file (bad chunk length).");
        std::vector<uint8_t> payload(plen);
        fin.read(reinterpret_cast<char*>(payload.data()), plen);
        if ((uint32_t)fin.gcount() != plen)
            throw std::runtime_error("Corrupted file (truncated chunk).");

        auto pt = AesGcmDecrypt(key, payload.data(), payload.data() + kNonceLen,
                                 payload.size() - kNonceLen);
        fout.write(reinterpret_cast<const char*>(pt.data()), (std::streamsize)pt.size());

        processed += 4 + plen;
        job.progress = total_size > 0
                            ? std::min(1.0f, (float)((double)processed / (double)total_size))
                            : 1.0f;
    }
}

void DecryptFile(const std::vector<uint8_t>& secret, const fs::path& in, const fs::path& out,
                  VaultJob& job) {
    std::error_code ec;
    uint64_t total_size = fs::file_size(in, ec);
    if (ec) { job.SetResult(false, "Could not stat input file: " + ec.message()); return; }

    fs::path tmp = out;
    tmp += ".part";

    std::ifstream fin(in, std::ios::binary);
    std::ofstream fout(tmp, std::ios::binary);
    if (!fin || !fout) { job.SetResult(false, "Could not open input/output file."); return; }

    try {
        uint8_t header[kHeaderLen];
        fin.read(reinterpret_cast<char*>(header), kHeaderLen);
        size_t got = (size_t)fin.gcount();

        std::string note;
        if (got >= 5 && std::memcmp(header, kMagic, 4) == 0) {
            if (header[4] != kFormatVersion)
                throw std::runtime_error("Unsupported file format version " +
                                          std::to_string((int)header[4]) + ".");
            if (got < kHeaderLen) throw std::runtime_error("Corrupted file header.");
            DecryptStreamV2(secret, fin, header, total_size, fout, job);
        } else {
            // Not a v2 file: treat as a legacy v1 file.
            fin.clear();
            fin.seekg(0);
            DecryptStreamV1(secret, fin, total_size, fout, job);
            note = " (legacy v1 file - re-encrypt it to get tamper and truncation protection)";
        }

        fout.flush();
        if (!fout) throw std::runtime_error("Write failed (disk full?).");
        fout.close();
        fin.close();

        fs::remove(out, ec);
        fs::rename(tmp, out);
        job.progress = 1.0f;
        job.SetResult(true, "File decrypted successfully." + note, out.string());
    } catch (const std::exception& e) {
        fout.close();
        std::error_code rm_ec;
        fs::remove(tmp, rm_ec);
        job.SetResult(false, std::string("Decryption failed: ") + e.what());
    }
}

// ---- folder archive (simple recursive path+size+bytes container) ---------
// Format per entry: [u16 path_len][path bytes, '/'-separated, utf-8]
//                    [u64 file_size][file bytes]
// Terminated by a path_len of 0.

static void WriteU16(std::ofstream& f, uint16_t v) {
    uint8_t b[2] = {uint8_t(v >> 8), uint8_t(v)};
    f.write(reinterpret_cast<const char*>(b), 2);
}
static void WriteU64(std::ofstream& f, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = uint8_t(v >> (8 * (7 - i)));
    f.write(reinterpret_cast<const char*>(b), 8);
}
static uint16_t ReadU16(std::ifstream& f) {
    uint8_t b[2];
    f.read(reinterpret_cast<char*>(b), 2);
    if (f.gcount() != 2) return 0;
    return (uint16_t(b[0]) << 8) | b[1];
}
static uint64_t ReadU64(std::ifstream& f) {
    uint8_t b[8];
    f.read(reinterpret_cast<char*>(b), 8);
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

// The temporary archive holds the folder's plaintext, so overwrite it once
// before deleting (best effort; see the shredding caveats in the README).
static void RemoveTempPlaintext(const fs::path& p) {
    std::error_code ec;
    try {
        VaultJob scratch;
        ShredFile(p, 1, scratch);
    } catch (...) {
    }
    fs::remove(p, ec);
}

void EncryptFolder(const std::vector<uint8_t>& secret, const fs::path& folder,
                    const fs::path& out, VaultJob& job) {
    try {
        fs::path abs_folder = fs::absolute(folder);
        fs::path temp_archive = fs::temp_directory_path() /
                                 ("securevault_archive_" + std::to_string(VAULT_GETPID()) + ".bin");

        std::vector<fs::path> files;
        for (auto& p : fs::recursive_directory_iterator(abs_folder)) {
            if (p.is_regular_file()) files.push_back(p.path());
        }

        {
            std::ofstream fout(temp_archive, std::ios::binary);
            if (!fout) throw std::runtime_error("Could not create temporary archive.");
            size_t n = files.size(), i = 0;
            for (auto& fp : files) {
                std::string rel = fs::relative(fp, abs_folder).generic_string();
                WriteU16(fout, (uint16_t)rel.size());
                fout.write(rel.data(), rel.size());

                uint64_t fsize = fs::file_size(fp);
                WriteU64(fout, fsize);

                std::ifstream fin(fp, std::ios::binary);
                std::vector<char> buf(kChunkSize);
                uint64_t remaining = fsize;
                while (remaining > 0) {
                    std::streamsize to_read = (std::streamsize)std::min<uint64_t>(remaining, kChunkSize);
                    fin.read(buf.data(), to_read);
                    fout.write(buf.data(), to_read);
                    remaining -= (uint64_t)to_read;
                }
                i++;
                job.progress = n > 0 ? 0.3f * ((float)i / (float)n) : 0.3f;  // archiving = first 30%
            }
            WriteU16(fout, 0);  // terminator
        }

        // Encrypt the archive; remaining 70% of progress comes from EncryptFile.
        VaultJob sub;
        EncryptFile(secret, temp_archive, out, sub);
        job.progress = 0.3f + 0.7f * sub.progress.load();
        RemoveTempPlaintext(temp_archive);

        if (sub.ok) {
            job.progress = 1.0f;
            job.SetResult(true, "Folder archived and encrypted successfully.", out.string());
        } else {
            job.SetResult(false, sub.result_text);
        }
    } catch (const std::exception& e) {
        job.SetResult(false, std::string("Folder encryption failed: ") + e.what());
    }
}

void DecryptFolder(const std::vector<uint8_t>& secret, const fs::path& archive,
                    const fs::path& out_folder, VaultJob& job) {
    try {
        fs::path temp_archive = fs::temp_directory_path() /
                                 ("securevault_restore_" + std::to_string(VAULT_GETPID()) + ".bin");

        VaultJob sub;
        DecryptFile(secret, archive, temp_archive, sub);
        job.progress = 0.6f * sub.progress.load();
        if (!sub.ok) {
            RemoveTempPlaintext(temp_archive);
            job.SetResult(false, sub.result_text);
            return;
        }

        fs::create_directories(out_folder);
        std::ifstream fin(temp_archive, std::ios::binary);
        if (!fin) throw std::runtime_error("Could not reopen decrypted archive.");

        while (true) {
            uint16_t path_len = ReadU16(fin);
            if (path_len == 0) break;
            std::string rel(path_len, '\0');
            fin.read(rel.data(), path_len);
            uint64_t fsize = ReadU64(fin);

            fs::path relp(rel);
            bool unsafe = rel.empty() || relp.is_absolute() || relp.has_root_name() ||
                          relp.has_root_directory();
            for (const auto& part : relp)
                if (part == "..") unsafe = true;
            if (unsafe || !fin) throw std::runtime_error("Archive contains an unsafe or corrupt entry.");

            fs::path dest = out_folder / relp;
            fs::create_directories(dest.parent_path());
            std::ofstream fout(dest, std::ios::binary);
            std::vector<char> buf(kChunkSize);
            uint64_t remaining = fsize;
            while (remaining > 0) {
                std::streamsize to_read = (std::streamsize)std::min<uint64_t>(remaining, kChunkSize);
                fin.read(buf.data(), to_read);
                fout.write(buf.data(), to_read);
                remaining -= (uint64_t)to_read;
            }
            job.progress = std::min(1.0f, job.progress.load() + 0.02f);
        }

        fin.close();
        RemoveTempPlaintext(temp_archive);
        job.progress = 1.0f;
        job.SetResult(true, "Folder restored successfully.", out_folder.string());
    } catch (const std::exception& e) {
        job.SetResult(false, std::string("Folder decryption failed: ") + e.what());
    }
}

// ---- hashing ---------------------------------------------------------------

std::string HashFile(const fs::path& path, HashAlgo algo, VaultJob& job) {
    std::error_code ec;
    uint64_t total_size = fs::file_size(path, ec);
    if (ec) { job.SetResult(false, "File not found."); return ""; }

    std::ifstream fin(path, std::ios::binary);
    if (!fin) { job.SetResult(false, "Could not open file."); return ""; }

    try {
        Hasher hasher(algo);
        std::vector<char> buf(kChunkSize);
        uint64_t processed = 0;
        while (fin) {
            fin.read(buf.data(), kChunkSize);
            std::streamsize got = fin.gcount();
            if (got <= 0) break;
            hasher.Update(reinterpret_cast<const uint8_t*>(buf.data()), (size_t)got);
            processed += (uint64_t)got;
            job.progress = total_size > 0 ? (float)((double)processed / (double)total_size) : 1.0f;
        }
        job.progress = 1.0f;
        std::string hex = hasher.FinalizeHex();
        job.SetResult(true, hex);
        return hex;
    } catch (const std::exception& e) {
        job.SetResult(false, std::string("Hashing failed: ") + e.what());
        return "";
    }
}

// ---- shredding ---------------------------------------------------------------

void ShredFile(const fs::path& path, int passes, VaultJob& job) {
    std::error_code ec;
    if (!fs::exists(path, ec)) return;
    uint64_t size = fs::file_size(path, ec);
    uint64_t total_work = std::max<uint64_t>(size * (uint64_t)passes, 1);
    uint64_t completed = 0;

    std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!f) throw std::runtime_error("Could not open file for shredding: " + path.string());

    for (int pass = 0; pass < passes; pass++) {
        f.seekp(0);
        uint64_t written = 0;
        while (written < size) {
            size_t chunk = (size_t)std::min<uint64_t>(kChunkSize, size - written);
            auto rnd = RandomBytes(chunk);
            f.write(reinterpret_cast<const char*>(rnd.data()), (std::streamsize)chunk);
            written += chunk;
            completed += chunk;
            job.progress = (float)((double)completed / (double)total_work);
        }
        f.flush();
    }
    f.close();
    fs::remove(path, ec);
}

void ShredPath(const fs::path& path, int passes, VaultJob& job) {
    try {
        std::error_code ec;
        if (!fs::exists(path, ec)) { job.SetResult(false, "Path does not exist."); return; }

        if (fs::is_directory(path, ec)) {
            std::vector<fs::path> files;
            for (auto& p : fs::recursive_directory_iterator(path))
                if (p.is_regular_file()) files.push_back(p.path());

            size_t n = files.size();
            for (size_t i = 0; i < n; i++) {
                VaultJob sub;
                ShredFile(files[i], passes, sub);
                job.progress = n > 0 ? (float)i / (float)n : 1.0f;
            }
            std::vector<fs::path> dirs;
            for (auto& p : fs::recursive_directory_iterator(path))
                if (p.is_directory()) dirs.push_back(p.path());
            std::sort(dirs.begin(), dirs.end(),
                      [](const fs::path& a, const fs::path& b) {
                          return a.string().size() > b.string().size();
                      });
            for (auto& d : dirs) fs::remove(d, ec);
            fs::remove(path, ec);
        } else {
            ShredFile(path, passes, job);
        }
        job.progress = 1.0f;
        job.SetResult(true, "Target permanently destroyed.");
    } catch (const std::exception& e) {
        job.SetResult(false, std::string("Shred failed: ") + e.what());
    }
}

}  // namespace vault
