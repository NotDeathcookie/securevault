// Tests for the SecureVault crypto and container format.
// Build with -DSECUREVAULT_BUILD_TESTS=ON, run the vault_tests binary.
// Exits non-zero on any failure.
#include "pathutil.hpp"
#include "vault.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

using namespace vault;

static int g_failures = 0, g_checks = 0;
#define CHECK(cond, msg)                                                          \
    do {                                                                          \
        g_checks++;                                                               \
        if (!(cond)) { g_failures++; std::printf("FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

using Bytes = std::vector<uint8_t>;

static fs::path g_dir;

static Bytes ReadAll(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
static void WriteAll(const fs::path& p, const Bytes& b) {
    std::ofstream f(p, std::ios::binary);
    f.write(reinterpret_cast<const char*>(b.data()), (std::streamsize)b.size());
}
static Bytes RandomData(size_t n, unsigned seed) {
    std::mt19937 rng(seed);
    Bytes b(n);
    for (auto& x : b) x = (uint8_t)rng();
    return b;
}

static const Bytes kSecret = {'c', 'o', 'r', 'r', 'e', 'c', 't', ' ', 'h', 'o', 'r', 's', 'e'};
static const Bytes kWrong  = {'w', 'r', 'o', 'n', 'g'};

static bool Enc(const Bytes& secret, const fs::path& in, const fs::path& out) {
    VaultJob j; EncryptFile(secret, in, out, j); return j.ok.load();
}
static bool Dec(const Bytes& secret, const fs::path& in, const fs::path& out) {
    VaultJob j; DecryptFile(secret, in, out, j); return j.ok.load();
}

// Offsets/sizes of each chunk (word + ciphertext) in a v2 file.
struct Span { size_t off, len; };
static std::vector<Span> Chunks(const Bytes& file) {
    std::vector<Span> v;
    size_t pos = 25;  // header
    while (pos + 4 <= file.size()) {
        uint32_t w = (uint32_t(file[pos]) << 24) | (uint32_t(file[pos + 1]) << 16) |
                     (uint32_t(file[pos + 2]) << 8) | uint32_t(file[pos + 3]);
        size_t ct = w & 0x7FFFFFFFu;
        v.push_back({pos, 4 + ct});
        pos += 4 + ct;
    }
    return v;
}

static void TestTextAndWrongPassword() {
    std::string enc = EncryptText(kSecret, "hello vault");
    CHECK(DecryptText(kSecret, enc) == "hello vault", "text round trip");
    bool threw = false;
    try { DecryptText(kWrong, enc); } catch (...) { threw = true; }
    CHECK(threw, "text: wrong password rejected");
}

static void TestRoundTripSizes() {
    const size_t sizes[] = {0, 1, 100, 65535, 65536, 65537, 131072, 200000};
    for (size_t n : sizes) {
        Bytes data = RandomData(n, (unsigned)n + 1);
        fs::path in = g_dir / "rt.bin", enc = g_dir / "rt.enc", dec = g_dir / "rt.dec";
        WriteAll(in, data);
        bool e = Enc(kSecret, in, enc);
        bool d = e && Dec(kSecret, enc, dec);
        CHECK(e && d, ("round trip ok, size " + std::to_string(n)).c_str());
        CHECK(d && ReadAll(dec) == data, ("round trip data matches, size " + std::to_string(n)).c_str());
    }
}

static void TestWrongPasswordFile() {
    fs::path in = g_dir / "wp.bin", enc = g_dir / "wp.enc", dec = g_dir / "wp.dec";
    WriteAll(in, RandomData(100000, 7));
    CHECK(Enc(kSecret, in, enc), "encrypt for wrong-password test");
    CHECK(!Dec(kWrong, enc, dec), "file: wrong password rejected");
    CHECK(!fs::exists(dec), "no output file left after failed decrypt");
    CHECK(!fs::exists(fs::path(dec.string() + ".part")), "no .part file left after failed decrypt");
}

static void TestTamperingAndTruncation() {
    fs::path in = g_dir / "t.bin", enc = g_dir / "t.enc", mod = g_dir / "t.mod", dec = g_dir / "t.dec";
    Bytes data = RandomData(65536 * 3 + 500, 99);  // 4 chunks (3 full + 1 partial)
    WriteAll(in, data);
    CHECK(Enc(kSecret, in, enc), "encrypt for tamper tests");
    Bytes good = ReadAll(enc);
    auto spans = Chunks(good);
    CHECK(spans.size() == 4, "expected 4 chunks");

    auto expectReject = [&](const Bytes& b, const char* what) {
        WriteAll(mod, b);
        fs::remove(dec);
        CHECK(!Dec(kSecret, mod, dec), what);
        CHECK(!fs::exists(dec), (std::string(what) + " (no output left)").c_str());
    };

    // 1. Remove the last chunk (the classic truncation attack).
    { Bytes b(good.begin(), good.begin() + spans[3].off); expectReject(b, "truncate: last chunk removed"); }
    // 2. Remove the last two chunks.
    { Bytes b(good.begin(), good.begin() + spans[2].off); expectReject(b, "truncate: last two chunks removed"); }
    // 3. Remove everything after the header.
    { Bytes b(good.begin(), good.begin() + 25); expectReject(b, "truncate: header only"); }
    // 4. Cut mid-chunk.
    { Bytes b(good.begin(), good.end() - 10); expectReject(b, "truncate: cut mid-chunk"); }
    // 5. Swap chunks 0 and 1.
    {
        Bytes b(good.begin(), good.begin() + 25);
        for (int idx : {1, 0, 2, 3})
            b.insert(b.end(), good.begin() + spans[idx].off, good.begin() + spans[idx].off + spans[idx].len);
        expectReject(b, "reorder: chunks 0 and 1 swapped");
    }
    // 6. Duplicate a chunk.
    {
        Bytes b(good.begin(), good.begin() + spans[1].off + spans[1].len);
        b.insert(b.end(), good.begin() + spans[1].off, good.begin() + spans[1].off + spans[1].len);
        b.insert(b.end(), good.begin() + spans[2].off, good.end());
        expectReject(b, "reorder: chunk duplicated");
    }
    // 7. Append trailing data.
    { Bytes b = good; for (int i = 0; i < 32; i++) b.push_back((uint8_t)i); expectReject(b, "append: trailing garbage"); }
    // 8. Flip one bit in the header (salt), version-safe area (chunk size field).
    { Bytes b = good; b[10] ^= 0x01; expectReject(b, "tamper: header bit flip"); }
    // 9. Flip one bit in a chunk body.
    { Bytes b = good; b[spans[1].off + 100] ^= 0x01; expectReject(b, "tamper: chunk body bit flip"); }
    // 10. Clear the final flag on the last chunk.
    { Bytes b = good; b[spans[3].off] &= 0x7F; expectReject(b, "tamper: final flag cleared"); }
    // 11. Set the final flag on a middle chunk.
    { Bytes b = good; b[spans[1].off] |= 0x80; expectReject(b, "tamper: final flag set early"); }
    // The unmodified file must still work.
    CHECK(Dec(kSecret, enc, dec) && ReadAll(dec) == data, "unmodified file still decrypts");
}

static void TestLegacyV1() {
    // Build a v1 file by hand: salt | [u32 len][nonce | ct+tag]...
    Bytes data = RandomData(70000, 5);
    Bytes salt = RandomBytes(kSaltLen);
    auto key = DeriveKey(kSecret, salt.data(), salt.size());
    Bytes file(salt.begin(), salt.end());
    for (size_t off = 0; off < data.size(); off += 65536) {
        size_t n = std::min<size_t>(65536, data.size() - off);
        Bytes nonce = RandomBytes(kNonceLen);
        Bytes ct = AesGcmEncrypt(key, nonce.data(), data.data() + off, n);
        uint32_t plen = (uint32_t)(nonce.size() + ct.size());
        uint8_t w[4] = {uint8_t(plen >> 24), uint8_t(plen >> 16), uint8_t(plen >> 8), uint8_t(plen)};
        file.insert(file.end(), w, w + 4);
        file.insert(file.end(), nonce.begin(), nonce.end());
        file.insert(file.end(), ct.begin(), ct.end());
    }
    fs::path enc = g_dir / "v1.enc", dec = g_dir / "v1.dec";
    WriteAll(enc, file);
    CHECK(Dec(kSecret, enc, dec), "legacy v1 file decrypts");
    CHECK(ReadAll(dec) == data, "legacy v1 data matches");
}

static void TestFolder() {
    fs::path src = g_dir / "folder_src", enc = g_dir / "folder.enc", out = g_dir / "folder_out";
    fs::create_directories(src / "sub" / "deep");
    WriteAll(src / "a.txt", RandomData(1000, 1));
    WriteAll(src / "sub" / "b.bin", RandomData(150000, 2));
    WriteAll(src / "sub" / "deep" / "empty.dat", Bytes());
    VaultJob j1; EncryptFolder(kSecret, src, enc, j1);
    CHECK(j1.ok.load(), "folder encrypt");
    VaultJob j2; DecryptFolder(kSecret, enc, out, j2);
    CHECK(j2.ok.load(), "folder decrypt");
    CHECK(ReadAll(out / "a.txt") == ReadAll(src / "a.txt"), "folder file a");
    CHECK(ReadAll(out / "sub" / "b.bin") == ReadAll(src / "sub" / "b.bin"), "folder file b");
    CHECK(fs::exists(out / "sub" / "deep" / "empty.dat"), "folder empty file kept");

    VaultJob j3; DecryptFolder(kWrong, enc, g_dir / "folder_bad", j3);
    CHECK(!j3.ok.load(), "folder: wrong password rejected");
}

static void TestPathTraversal() {
    // Hand-build an archive with a "../evil.txt" entry, encrypt it, and make
    // sure DecryptFolder refuses to write outside the destination.
    Bytes arc;
    std::string rel = "../evil.txt";
    arc.push_back(0); arc.push_back((uint8_t)rel.size());
    arc.insert(arc.end(), rel.begin(), rel.end());
    for (int i = 0; i < 7; i++) arc.push_back(0);
    arc.push_back(4);  // size = 4
    for (char c : std::string("evil")) arc.push_back((uint8_t)c);
    arc.push_back(0); arc.push_back(0);  // terminator

    fs::path plain = g_dir / "evil.arc", enc = g_dir / "evil.enc";
    WriteAll(plain, arc);
    CHECK(Enc(kSecret, plain, enc), "encrypt crafted archive");

    fs::path dest = g_dir / "evil_dest";
    VaultJob j; DecryptFolder(kSecret, enc, dest, j);
    CHECK(!j.ok.load(), "path traversal archive rejected");
    CHECK(!fs::exists(g_dir / "evil.txt"), "nothing written outside destination");
}

static void TestPathCleaning() {
    using pathutil::CleanPath;
    CHECK(CleanPath("\"C:\\Users\\me\\my file.txt\"") == "C:\\Users\\me\\my file.txt", "strips Windows copy-as-path quotes");
    CHECK(CleanPath("  \"C:\\x\"  ") == "C:\\x", "trims spaces around quoted path");
    CHECK(CleanPath("'/home/me/a b'") == "/home/me/a b", "strips single quotes");
    CHECK(CleanPath("\xE2\x80\x9C" "C:\\x" "\xE2\x80\x9D") == "C:\\x", "strips curly double quotes");
    CHECK(CleanPath("C:\\no quotes here") == "C:\\no quotes here", "leaves unquoted paths alone");
    CHECK(CleanPath("\"unmatched") == "\"unmatched", "leaves an unmatched quote alone");
    CHECK(CleanPath("\"\"") == "", "empty quotes become empty");
    CHECK(CleanPath("\"\"C:\\x\"\"") == "C:\\x", "strips doubled quotes");
    CHECK(CleanPath("   ") == "", "whitespace only becomes empty");

    char buf[64] = "\"C:\\a b\"";
    pathutil::StripQuotesInPlace(buf, sizeof(buf));
    CHECK(std::string(buf) == "C:\\a b", "in-place strip while editing");
    char typing[64] = "C:\\a ";
    pathutil::StripQuotesInPlace(typing, sizeof(typing));
    CHECK(std::string(typing) == "C:\\a ", "in-place strip keeps trailing space while typing");
}

int main() {
    std::random_device rd;
    g_dir = fs::temp_directory_path() / ("svtests_" + std::to_string(rd()));
    fs::create_directories(g_dir);

    TestPathCleaning();
    TestTextAndWrongPassword();
    TestRoundTripSizes();
    TestWrongPasswordFile();
    TestTamperingAndTruncation();
    TestLegacyV1();
    TestFolder();
    TestPathTraversal();

    std::error_code ec;
    fs::remove_all(g_dir, ec);
    std::printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
