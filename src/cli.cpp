// securevault-cli - command-line front end for the same engine the GUI uses.
//
//   securevault-cli encrypt <file|folder> [-o OUT] [auth] [--force]
//   securevault-cli decrypt <file>        [-o OUT] [auth] [--force] [--folder]
//   securevault-cli verify  <file>        [auth]
//   securevault-cli inspect <file>
//   securevault-cli hash    <file> [--algo sha256|sha512|sha384|sha1|md5]
//   securevault-cli shred   <file|folder> [--passes N] [--yes]
//   securevault-cli genkey  <file> [--force]
//   securevault-cli genpass [--length N] [--no-symbols] | [--words N]
//
// auth: --keyfile FILE | --password-env NAME | --password-stdin | (hidden prompt)
// A password is never accepted as a command-line argument: it would end up in
// shell history and in the process list.
// Exit codes: 0 success, 1 operation failed, 2 usage error.

#include "generator.hpp"
#include "pathutil.hpp"
#include "vault.hpp"
#include "version.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <windows.h>
  #include <shellapi.h>
  #include <io.h>
  // windows.h defines EncryptFile/DecryptFile as macros for its own file-encryption
  // API, which would rewrite our vault::EncryptFile calls.
  #undef EncryptFile
  #undef DecryptFile
#else
  #include <termios.h>
  #include <unistd.h>
#endif

static const char* kVersion = SV_VERSION;

namespace {

using Bytes = std::vector<uint8_t>;

struct Options {
    std::string command;
    std::vector<std::string> positional;
    std::string keyfile, passwordEnv, output, algo = "sha256";
    bool passwordStdin = false, force = false, yes = false, folder = false, noSymbols = false;
    bool help = false;
    int passes = 2, length = 20, words = 0;
};

int Usage(const char* why = nullptr) {
    if (why) std::fprintf(stderr, "Error: %s\n\n", why);
    std::fprintf(stderr,
        "SecureVault command line, version %s\n\n"
        "Usage:\n"
        "  securevault-cli encrypt <file|folder> [-o OUT] [auth] [--force]\n"
        "  securevault-cli decrypt <file>        [-o OUT] [auth] [--force] [--folder]\n"
        "  securevault-cli verify  <file>        [auth]\n"
        "  securevault-cli inspect <file>\n"
        "  securevault-cli hash    <file> [--algo sha256|sha512|sha384|sha1|md5]\n"
        "  securevault-cli shred   <file|folder> [--passes N] [--yes]\n"
        "  securevault-cli genkey  <file> [--force]\n"
        "  securevault-cli genpass [--length N] [--no-symbols]   (or: --words N)\n\n"
        "auth (pick one; with none, you are asked for a password with hidden input):\n"
        "  --keyfile FILE        use a file as the key\n"
        "  --password-env NAME   read the password from an environment variable\n"
        "  --password-stdin      read the password from one line of standard input\n\n"
        "Exit codes: 0 success, 1 failed, 2 usage error.\n", kVersion);
    return 2;
}

int Fail(const std::string& message) {
    std::fprintf(stderr, "Error: %s\n", message.c_str());
    return 1;
}

// ---- platform helpers ------------------------------------------------------

#if defined(_WIN32)
std::string ToUtf8(const wchar_t* w) {
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "";
    std::string s((size_t)len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
    return s;
}
std::wstring ToWide(const std::string& s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 1) return L"";
    std::wstring w((size_t)len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len);
    return w;
}
bool StdinIsTty() { return _isatty(_fileno(stdin)) != 0; }
bool StderrIsTty() { return _isatty(_fileno(stderr)) != 0; }

std::string GetEnvUtf8(const std::string& name, bool& found) {
    std::wstring wname = ToWide(name);
    DWORD need = GetEnvironmentVariableW(wname.c_str(), nullptr, 0);
    if (need == 0) { found = false; return ""; }
    std::wstring buf(need, L'\0');
    GetEnvironmentVariableW(wname.c_str(), buf.data(), need);
    found = true;
    return ToUtf8(buf.c_str());
}

// Reads one line without echo. Returns false if it could not.
bool ReadHidden(std::string& out) {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode)) return false;
    SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
    wchar_t buf[1024];
    DWORD n = 0;
    BOOL ok = ReadConsoleW(h, buf, 1023, &n, nullptr);
    SetConsoleMode(h, mode);
    std::fputc('\n', stderr);
    if (!ok) return false;
    while (n > 0 && (buf[n - 1] == L'\r' || buf[n - 1] == L'\n')) n--;
    buf[n] = L'\0';
    out = ToUtf8(buf);
    SecureZeroMemory(buf, sizeof(buf));
    return true;
}
#else
bool StdinIsTty() { return isatty(STDIN_FILENO) != 0; }
bool StderrIsTty() { return isatty(STDERR_FILENO) != 0; }

std::string GetEnvUtf8(const std::string& name, bool& found) {
    const char* v = std::getenv(name.c_str());
    found = v != nullptr;
    return v ? v : "";
}

bool ReadHidden(std::string& out) {
    termios oldt{};
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) return false;
    termios newt = oldt;
    newt.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    bool ok = static_cast<bool>(std::getline(std::cin, out));
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::fputc('\n', stderr);
    return ok;
}
#endif

// ---- authentication ----------------------------------------------------------

bool ReadKeyFile(const std::string& path, Bytes& out, std::string& err) {
    std::ifstream f(pathutil::ToPath(pathutil::CleanPath(path)), std::ios::binary);
    if (!f) { err = "Could not open the key file."; return false; }
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    if (out.empty()) { err = "The key file is empty."; return false; }
    return true;
}

bool GetSecret(const Options& o, bool confirm, Bytes& secret, std::string& err) {
    int sources = (!o.keyfile.empty()) + (!o.passwordEnv.empty()) + (o.passwordStdin ? 1 : 0);
    if (sources > 1) { err = "Choose only one of --keyfile, --password-env, --password-stdin."; return false; }

    if (!o.keyfile.empty()) return ReadKeyFile(o.keyfile, secret, err);

    std::string pw;
    if (!o.passwordEnv.empty()) {
        bool found = false;
        pw = GetEnvUtf8(o.passwordEnv, found);
        if (!found) { err = "Environment variable " + o.passwordEnv + " is not set."; return false; }
    } else if (o.passwordStdin) {
        if (!std::getline(std::cin, pw)) { err = "No password on standard input."; return false; }
        while (!pw.empty() && (pw.back() == '\r' || pw.back() == '\n')) pw.pop_back();
    } else {
        if (!StdinIsTty()) {
            err = "No password source. Use --keyfile, --password-env, or --password-stdin.";
            return false;
        }
        std::fprintf(stderr, "Password: ");
        std::fflush(stderr);
        if (!ReadHidden(pw)) { err = "Could not read the password."; return false; }
        if (confirm) {
            std::fprintf(stderr, "Repeat password: ");
            std::fflush(stderr);
            std::string again;
            if (!ReadHidden(again) || again != pw) { err = "The passwords do not match."; return false; }
        }
    }
    if (pw.empty()) { err = "The password is empty."; return false; }
    secret.assign(pw.begin(), pw.end());
    return true;
}

// ---- running an operation with a progress line ------------------------------

bool RunJob(const std::function<void(vault::VaultJob&)>& fn, const char* label, std::string& message) {
    vault::VaultJob job;
    job.running = true;
    std::atomic<bool> finished{false};
    std::thread t([&] { fn(job); finished = true; });

    const bool tty = StderrIsTty();
    int last = -1;
    while (!finished.load()) {
        if (tty) {
            int pct = (int)(job.progress.load() * 100.0f);
            if (pct != last) { std::fprintf(stderr, "\r%s %3d%%", label, pct); std::fflush(stderr); last = pct; }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(60));
    }
    t.join();
    if (tty && last >= 0) std::fprintf(stderr, "\r%*s\r", 40, "");

    if (!job.done.load()) { message = "The operation did not report a result."; return false; }
    {
        std::lock_guard<std::mutex> lk(job.result_mutex);
        message = job.result_text;
    }
    return job.ok.load();
}

// ---- commands -------------------------------------------------------------------

bool CheckOutput(const std::string& out, bool force, std::string& err) {
    std::error_code ec;
    if (!force && std::filesystem::exists(pathutil::ToPath(out), ec)) {
        err = "'" + out + "' already exists. Use --force to replace it, or -o to pick another name.";
        return false;
    }
    return true;
}

int CmdEncrypt(const Options& o) {
    if (o.positional.size() != 1) return Usage("encrypt needs exactly one file or folder.");
    std::string in = pathutil::CleanPath(o.positional[0]);
    std::error_code ec;
    auto p = pathutil::ToPath(in);
    if (!std::filesystem::exists(p, ec)) return Fail("'" + in + "' does not exist.");
    bool isDir = std::filesystem::is_directory(p, ec);

    std::string out = !o.output.empty() ? pathutil::CleanPath(o.output)
                                        : (isDir ? pathutil::FolderOutputPath(in, true)
                                                 : pathutil::FileOutputPath(in, true));
    std::string err;
    if (!CheckOutput(out, o.force, err)) return Fail(err);
    Bytes secret;
    if (!GetSecret(o, true, secret, err)) return Fail(err);

    std::string msg;
    bool ok = RunJob([&](vault::VaultJob& j) {
        if (isDir) vault::EncryptFolder(secret, p, pathutil::ToPath(out), j);
        else       vault::EncryptFile(secret, p, pathutil::ToPath(out), j);
    }, "Encrypting", msg);
    if (!ok) return Fail(msg);
    std::printf("Encrypted: %s\n", out.c_str());
    return 0;
}

int CmdDecrypt(const Options& o) {
    if (o.positional.size() != 1) return Usage("decrypt needs exactly one file.");
    std::string in = pathutil::CleanPath(o.positional[0]);
    std::error_code ec;
    auto p = pathutil::ToPath(in);
    if (!std::filesystem::is_regular_file(p, ec)) return Fail("'" + in + "' is not a file.");
    bool isFolder = o.folder || pathutil::EndsWith(in, "_folder.enc");

    std::string out = !o.output.empty() ? pathutil::CleanPath(o.output)
                                        : (isFolder ? pathutil::FolderOutputPath(in, false)
                                                    : pathutil::FileOutputPath(in, false));
    std::string err;
    if (!CheckOutput(out, o.force, err)) return Fail(err);
    Bytes secret;
    if (!GetSecret(o, false, secret, err)) return Fail(err);

    std::string msg;
    bool ok = RunJob([&](vault::VaultJob& j) {
        if (isFolder) vault::DecryptFolder(secret, p, pathutil::ToPath(out), j);
        else          vault::DecryptFile(secret, p, pathutil::ToPath(out), j);
    }, "Decrypting", msg);
    if (!ok) return Fail(msg);
    std::printf("Decrypted: %s\n", out.c_str());
    if (msg.find("legacy v1") != std::string::npos)
        std::fprintf(stderr, "Note: this is a legacy v1 file. Re-encrypt it to get tamper protection.\n");
    return 0;
}

int CmdVerify(const Options& o) {
    if (o.positional.size() != 1) return Usage("verify needs exactly one file.");
    std::string in = pathutil::CleanPath(o.positional[0]);
    std::string err;
    Bytes secret;
    if (!GetSecret(o, false, secret, err)) return Fail(err);
    std::string msg;
    bool ok = RunJob([&](vault::VaultJob& j) { vault::VerifyFile(secret, pathutil::ToPath(in), j); },
                     "Verifying", msg);
    if (!ok) return Fail(msg);
    std::printf("%s\n", msg.c_str());
    return 0;
}

int CmdInspect(const Options& o) {
    if (o.positional.size() != 1) return Usage("inspect needs exactly one file.");
    vault::FileInfo info = vault::InspectFile(pathutil::ToPath(pathutil::CleanPath(o.positional[0])));
    std::printf("%s\n", info.summary.c_str());
    return (info.readable && info.structure_ok) ? 0 : 1;
}

int CmdHash(const Options& o) {
    if (o.positional.size() != 1) return Usage("hash needs exactly one file.");
    vault::HashAlgo algo;
    if (o.algo == "sha256") algo = vault::HashAlgo::SHA256;
    else if (o.algo == "sha512") algo = vault::HashAlgo::SHA512;
    else if (o.algo == "sha384") algo = vault::HashAlgo::SHA384;
    else if (o.algo == "sha1") algo = vault::HashAlgo::SHA1;
    else if (o.algo == "md5") algo = vault::HashAlgo::MD5;
    else return Usage("unknown --algo (use sha256, sha512, sha384, sha1, or md5).");

    std::string in = pathutil::CleanPath(o.positional[0]);
    std::string msg;
    bool ok = RunJob([&](vault::VaultJob& j) { vault::HashFile(pathutil::ToPath(in), algo, j); },
                     "Hashing", msg);
    if (!ok) return Fail(msg);
    std::printf("%s  %s\n", msg.c_str(), in.c_str());
    return 0;
}

int CmdShred(const Options& o) {
    if (o.positional.size() != 1) return Usage("shred needs exactly one file or folder.");
    std::string in = pathutil::CleanPath(o.positional[0]);
    if (o.passes < 1 || o.passes > 5) return Usage("--passes must be between 1 and 5.");
    std::error_code ec;
    if (!std::filesystem::exists(pathutil::ToPath(in), ec)) return Fail("'" + in + "' does not exist.");

    if (!o.yes) {
        if (!StdinIsTty()) return Fail("Refusing to shred without --yes.");
        std::fprintf(stderr, "This permanently destroys '%s'. Type YES to continue: ", in.c_str());
        std::fflush(stderr);
        std::string answer;
        std::getline(std::cin, answer);
        if (answer != "YES") return Fail("Cancelled.");
    }
    std::string msg;
    bool ok = RunJob([&](vault::VaultJob& j) { vault::ShredPath(pathutil::ToPath(in), o.passes, j); },
                     "Shredding", msg);
    if (!ok) return Fail(msg);
    std::printf("Destroyed: %s\n", in.c_str());
    return 0;
}

int CmdGenKey(const Options& o) {
    if (o.positional.size() != 1) return Usage("genkey needs a file name to write.");
    std::string out = pathutil::CleanPath(o.positional[0]);
    std::string err;
    if (!CheckOutput(out, o.force, err)) return Fail(err);
    if (!generator::WriteKeyFile(pathutil::ToPath(out), generator::kKeyFileBytes, err)) return Fail(err);
    std::printf("Wrote %zu-byte key file: %s\n", generator::kKeyFileBytes, out.c_str());
    std::fprintf(stderr, "Keep a backup. Anything encrypted with it cannot be opened without this exact file.\n");
    return 0;
}

int CmdGenPass(const Options& o) {
    try {
        if (o.words > 0) {
            std::printf("%s\n", generator::GeneratePassphrase(o.words).c_str());
            std::fprintf(stderr, "~%.0f bits of entropy\n", generator::PassphraseBits(o.words));
        } else {
            generator::PasswordOptions po;
            po.length = o.length;
            po.symbols = !o.noSymbols;
            std::printf("%s\n", generator::GeneratePassword(po).c_str());
            std::fprintf(stderr, "~%.0f bits of entropy\n", generator::PasswordBits(po));
        }
        return 0;
    } catch (const std::exception& e) {
        return Fail(e.what());
    }
}

bool ParseInt(const std::string& s, int& out) {
    try { size_t used = 0; out = std::stoi(s, &used); return used == s.size(); }
    catch (...) { return false; }
}

}  // namespace

int RealMain(const std::vector<std::string>& args) {
    if (args.size() < 2) return Usage();
    Options o;
    o.command = args[1];
    if (o.command == "help" || o.command == "--help" || o.command == "-h") { Usage(); return 0; }
    if (o.command == "version" || o.command == "--version") { std::printf("securevault-cli %s\n", kVersion); return 0; }

    for (size_t i = 2; i < args.size(); i++) {
        const std::string& a = args[i];
        auto value = [&](std::string& dst) -> bool {
            if (i + 1 >= args.size()) return false;
            dst = args[++i];
            return true;
        };
        auto intValue = [&](int& dst) -> bool {
            std::string s;
            return value(s) && ParseInt(s, dst);
        };
        if (a == "--keyfile") { if (!value(o.keyfile)) return Usage("--keyfile needs a value."); }
        else if (a == "--password-env") { if (!value(o.passwordEnv)) return Usage("--password-env needs a name."); }
        else if (a == "-o" || a == "--output") { if (!value(o.output)) return Usage("-o needs a value."); }
        else if (a == "--algo") { if (!value(o.algo)) return Usage("--algo needs a value."); }
        else if (a == "--passes") { if (!intValue(o.passes)) return Usage("--passes needs a number."); }
        else if (a == "--length") { if (!intValue(o.length)) return Usage("--length needs a number."); }
        else if (a == "--words") { if (!intValue(o.words)) return Usage("--words needs a number."); }
        else if (a == "--password-stdin") o.passwordStdin = true;
        else if (a == "--force") o.force = true;
        else if (a == "--yes" || a == "-y") o.yes = true;
        else if (a == "--folder") o.folder = true;
        else if (a == "--no-symbols") o.noSymbols = true;
        else if (a == "--password" || a.rfind("--password=", 0) == 0)
            return Usage("passwords are not accepted as arguments (they would show up in shell history). "
                         "Use the prompt, --password-env, --password-stdin, or --keyfile.");
        else if (a.size() > 1 && a[0] == '-') return Usage(("unknown option " + a).c_str());
        else o.positional.push_back(a);
    }

    if (o.command == "encrypt") return CmdEncrypt(o);
    if (o.command == "decrypt") return CmdDecrypt(o);
    if (o.command == "verify")  return CmdVerify(o);
    if (o.command == "inspect") return CmdInspect(o);
    if (o.command == "hash")    return CmdHash(o);
    if (o.command == "shred")   return CmdShred(o);
    if (o.command == "genkey")  return CmdGenKey(o);
    if (o.command == "genpass") return CmdGenPass(o);
    return Usage(("unknown command '" + o.command + "'").c_str());
}

int main(int argc, char** argv) {
    std::vector<std::string> args;
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
    (void)argc; (void)argv;
    int wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    for (int i = 0; wargv && i < wargc; i++) args.push_back(ToUtf8(wargv[i]));
    if (wargv) LocalFree(wargv);

    // If this program was started by double-clicking it, Windows opened a console
    // window just for it, and that window vanishes the moment we exit. In that case
    // (we are the only process attached to the console) explain and wait for Enter.
    DWORD attached[2];
    const bool ownsConsole = GetConsoleProcessList(attached, 2) == 1;

    int rc = RealMain(args);

    if (ownsConsole) {
        if (args.size() < 2)
            std::fprintf(stderr,
                "\nThis is a command-line tool, so it is meant to be run from a terminal.\n"
                "Open PowerShell or Command Prompt in this folder and try, for example:\n"
                "    .\\securevault-cli.exe help\n"
                "    .\\securevault-cli.exe genpass --words 6\n"
                "For the windowed app, run securevault.exe instead.\n");
        std::fprintf(stderr, "\nPress Enter to close this window...");
        std::fflush(stderr);
        std::string ignored;
        std::getline(std::cin, ignored);
    }
    return rc;
#else
    for (int i = 0; i < argc; i++) args.push_back(argv[i]);
    return RealMain(args);
#endif
}
