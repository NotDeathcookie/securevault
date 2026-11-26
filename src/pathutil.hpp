// pathutil.hpp - helpers for paths typed or pasted into the UI.
#pragma once

#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <string>

namespace pathutil {

inline std::string Trim(const std::string& s) {
    const char* ws = " \t\r\n";
    size_t a = s.find_first_not_of(ws);
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(ws);
    return s.substr(a, b - a + 1);
}

// Removes ONE pair of matching quotes around the whole string: "..." or '...'
// or the curly versions. Windows "Copy as path" wraps paths in double quotes.
inline bool StripOnePair(std::string& s) {
    if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') ||
                          (s.front() == '\'' && s.back() == '\''))) {
        s = s.substr(1, s.size() - 2);
        return true;
    }
    // UTF-8 curly quotes: U+201C/U+201D (E2 80 9C / 9D), U+2018/U+2019 (E2 80 98 / 99)
    if (s.size() >= 6 && s.compare(0, 2, "\xE2\x80") == 0 &&
        s.compare(s.size() - 3, 2, "\xE2\x80") == 0) {
        unsigned char o = (unsigned char)s[2], c = (unsigned char)s[s.size() - 1];
        if ((o == 0x9C && c == 0x9D) || (o == 0x98 && c == 0x99)) {
            s = s.substr(3, s.size() - 6);
            return true;
        }
    }
    return false;
}

// Full clean-up used when a path is actually used: trim spaces, then peel off
// any surrounding quotes. Never use this on passwords.
inline std::string CleanPath(std::string s) {
    s = Trim(s);
    while (StripOnePair(s)) s = Trim(s);
    return s;
}

// Used while editing a text box: strips a surrounding quote pair the moment a
// pasted path lands, without trimming (so you can still type spaces).
inline void StripQuotesInPlace(char* buf, size_t cap) {
    std::string s(buf);
    if (StripOnePair(s)) std::snprintf(buf, cap, "%s", s.c_str());
}

// The UI works in UTF-8; on Windows std::filesystem needs to be told that.
inline std::filesystem::path ToPath(const std::string& utf8) {
#if defined(_WIN32)
    return std::filesystem::u8path(utf8);
#else
    return std::filesystem::path(utf8);
#endif
}

}  // namespace pathutil
