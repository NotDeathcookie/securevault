// generator.hpp - random passwords, passphrases, and key files.
// All randomness comes from the operating system's cryptographic RNG
// (via vault::RandomBytes), with rejection sampling so every choice is uniform.
#pragma once

#include <filesystem>
#include <string>

namespace generator {

struct PasswordOptions {
    int length = 20;
    bool lower = true;
    bool upper = true;
    bool digits = true;
    bool symbols = true;
};

constexpr int kMinPasswordLength = 8;
constexpr int kMaxPasswordLength = 128;
constexpr int kMinWords = 4;
constexpr int kMaxWords = 16;
constexpr size_t kKeyFileBytes = 64;  // 512 bits

// Size of the character set the options select (0 if nothing is selected).
int CharsetSize(const PasswordOptions& o);

// Throws std::runtime_error if no character class is selected. When several
// classes are selected, the result is guaranteed to contain at least one of each.
std::string GeneratePassword(const PasswordOptions& o);
double PasswordBits(const PasswordOptions& o);

// `words` random words from the 2048-word list, joined by `separator`.
std::string GeneratePassphrase(int words, const std::string& separator = "-");
double PassphraseBits(int words);

// Uniform random number in [0, n). n must be > 0.
unsigned RandomBelow(unsigned n);

// Writes `bytes` random bytes to `path` (an existing file is replaced).
// Returns false and fills `error` on failure.
bool WriteKeyFile(const std::filesystem::path& path, size_t bytes, std::string& error);

}  // namespace generator
