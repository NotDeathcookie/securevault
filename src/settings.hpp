// settings.hpp - the few preferences worth remembering between runs.
// Stored as plain key=value lines in <config dir>/<app dir>/ui.ini
// (Windows: %APPDATA%, Linux: $XDG_CONFIG_HOME or ~/.config).
// Never stores passwords, key file contents, or any text from the screen.
#pragma once

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <istream>
#include <ostream>
#include <string>

namespace settings {

struct Ui {
    int autoLockIdx = 2;     // index into the auto-lock choices (0 = off)
    bool privateMode = false;
    int hashAlgoIdx = 0;
    int shredPasses = 2;
    int genMode = 0;         // 0 = password, 1 = passphrase
    int genLength = 20;
    bool genLower = true, genUpper = true, genDigits = true, genSymbols = true;
    int genWords = 6;

    bool operator==(const Ui& o) const {
        return autoLockIdx == o.autoLockIdx && privateMode == o.privateMode &&
               hashAlgoIdx == o.hashAlgoIdx && shredPasses == o.shredPasses && genMode == o.genMode &&
               genLength == o.genLength && genLower == o.genLower && genUpper == o.genUpper &&
               genDigits == o.genDigits && genSymbols == o.genSymbols && genWords == o.genWords;
    }
};

inline int ClampInt(int v, int lo, int hi) { return std::min(hi, std::max(lo, v)); }

// Keeps every value inside what the UI can display, so a hand-edited or damaged
// file can never put the app into an invalid state.
inline void Clamp(Ui& u) {
    u.autoLockIdx = ClampInt(u.autoLockIdx, 0, 4);
    u.hashAlgoIdx = ClampInt(u.hashAlgoIdx, 0, 4);
    u.shredPasses = ClampInt(u.shredPasses, 1, 5);
    u.genMode = ClampInt(u.genMode, 0, 1);
    u.genLength = ClampInt(u.genLength, 8, 64);
    u.genWords = ClampInt(u.genWords, 4, 12);
    if (!u.genLower && !u.genUpper && !u.genDigits && !u.genSymbols) u.genLower = true;
}

inline std::filesystem::path FilePath(const std::string& appDir) {
    namespace fs = std::filesystem;
#if defined(_WIN32)
    const char* base = std::getenv("APPDATA");
    fs::path root = base ? fs::path(base) : fs::path(".");
#else
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    const char* home = std::getenv("HOME");
    fs::path root = (xdg && *xdg) ? fs::path(xdg) : (home ? fs::path(home) / ".config" : fs::path("."));
#endif
    return root / appDir / "ui.ini";
}

inline void Write(std::ostream& o, const Ui& u) {
    o << "auto_lock_index=" << u.autoLockIdx << "\n"
      << "private_mode=" << (u.privateMode ? 1 : 0) << "\n"
      << "hash_algorithm=" << u.hashAlgoIdx << "\n"
      << "shred_passes=" << u.shredPasses << "\n"
      << "generator_mode=" << u.genMode << "\n"
      << "password_length=" << u.genLength << "\n"
      << "password_lower=" << (u.genLower ? 1 : 0) << "\n"
      << "password_upper=" << (u.genUpper ? 1 : 0) << "\n"
      << "password_digits=" << (u.genDigits ? 1 : 0) << "\n"
      << "password_symbols=" << (u.genSymbols ? 1 : 0) << "\n"
      << "passphrase_words=" << u.genWords << "\n";
}

// Unknown keys, malformed lines, and out-of-range numbers are ignored or clamped.
inline Ui Parse(std::istream& in) {
    Ui u;
    std::string line;
    while (std::getline(in, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq), val = line.substr(eq + 1);
        int n = 0;
        try { size_t used = 0; n = std::stoi(val, &used); if (used == 0) continue; }
        catch (...) { continue; }
        if (key == "auto_lock_index") u.autoLockIdx = n;
        else if (key == "private_mode") u.privateMode = n != 0;
        else if (key == "hash_algorithm") u.hashAlgoIdx = n;
        else if (key == "shred_passes") u.shredPasses = n;
        else if (key == "generator_mode") u.genMode = n;
        else if (key == "password_length") u.genLength = n;
        else if (key == "password_lower") u.genLower = n != 0;
        else if (key == "password_upper") u.genUpper = n != 0;
        else if (key == "password_digits") u.genDigits = n != 0;
        else if (key == "password_symbols") u.genSymbols = n != 0;
        else if (key == "passphrase_words") u.genWords = n;
    }
    Clamp(u);
    return u;
}

inline Ui Load(const std::filesystem::path& p) {
    std::ifstream f(p);
    if (!f) return Ui();
    return Parse(f);
}

inline bool Save(const std::filesystem::path& p, const Ui& u) {
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    std::ofstream f(p, std::ios::trunc);
    if (!f) return false;
    Write(f, u);
    f.flush();
    return static_cast<bool>(f);
}

}  // namespace settings
