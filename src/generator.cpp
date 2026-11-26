#include "generator.hpp"

#include "vault_crypto.hpp"
#include "wordlist.hpp"

#include <cmath>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace generator {

static const char kLower[]   = "abcdefghijklmnopqrstuvwxyz";
static const char kUpper[]   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char kDigits[]  = "0123456789";
static const char kSymbols[] = "!@#$%^&*-_=+?.,:;";

unsigned RandomBelow(unsigned n) {
    if (n == 0) throw std::invalid_argument("RandomBelow(0)");
    // Reject values from the incomplete last "bucket" so every result is equally likely.
    const uint32_t limit = (0xFFFFFFFFu / n) * n;
    for (;;) {
        auto b = vault::RandomBytes(4);
        uint32_t v = (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8) | b[3];
        if (v < limit) return v % n;
    }
}

int CharsetSize(const PasswordOptions& o) {
    int n = 0;
    if (o.lower)   n += (int)sizeof(kLower) - 1;
    if (o.upper)   n += (int)sizeof(kUpper) - 1;
    if (o.digits)  n += (int)sizeof(kDigits) - 1;
    if (o.symbols) n += (int)sizeof(kSymbols) - 1;
    return n;
}

static bool Contains(const std::string& s, const char* set) {
    return s.find_first_of(set) != std::string::npos;
}

std::string GeneratePassword(const PasswordOptions& o) {
    std::string charset;
    int classes = 0;
    if (o.lower)   { charset += kLower;   classes++; }
    if (o.upper)   { charset += kUpper;   classes++; }
    if (o.digits)  { charset += kDigits;  classes++; }
    if (o.symbols) { charset += kSymbols; classes++; }
    if (charset.empty()) throw std::runtime_error("Select at least one character type.");

    int len = o.length;
    if (len < kMinPasswordLength) len = kMinPasswordLength;
    if (len > kMaxPasswordLength) len = kMaxPasswordLength;

    // Draw uniformly; retry until every selected class appears. (Retrying keeps
    // the result uniform among passwords that satisfy the rule.)
    for (;;) {
        std::string pw;
        pw.reserve((size_t)len);
        for (int i = 0; i < len; i++) pw += charset[RandomBelow((unsigned)charset.size())];
        if ((!o.lower   || Contains(pw, kLower))  && (!o.upper   || Contains(pw, kUpper)) &&
            (!o.digits  || Contains(pw, kDigits)) && (!o.symbols || Contains(pw, kSymbols)))
            return pw;
    }
}

double PasswordBits(const PasswordOptions& o) {
    int n = CharsetSize(o);
    if (n <= 1) return 0.0;
    return o.length * std::log2((double)n);
}

std::string GeneratePassphrase(int words, const std::string& separator) {
    if (words < kMinWords) words = kMinWords;
    if (words > kMaxWords) words = kMaxWords;
    std::string out;
    for (int i = 0; i < words; i++) {
        if (i) out += separator;
        out += kWords[RandomBelow((unsigned)kWordCount)];
    }
    return out;
}

double PassphraseBits(int words) { return words * std::log2((double)kWordCount); }

bool WriteKeyFile(const std::filesystem::path& path, size_t bytes, std::string& error) {
    try {
        auto data = vault::RandomBytes(bytes);
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) { error = "Could not create the file."; return false; }
        f.write(reinterpret_cast<const char*>(data.data()), (std::streamsize)data.size());
        f.flush();
        if (!f) { error = "Write failed (disk full or no permission)."; return false; }
        f.close();
#if !defined(_WIN32)
        std::error_code ec;  // owner read/write only, like an SSH key
        std::filesystem::permissions(path, std::filesystem::perms::owner_read |
                                               std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace, ec);
#endif
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

}  // namespace generator
