// Secure Vault GUI
// A C++ / Dear ImGui rewrite of secure_vault-wy-hash.py, styled after the
// pink-neon "card dashboard" reference screenshot.
//
// AES-256-GCM + PBKDF2-HMAC-SHA256 crypto lives in vault.{hpp,cpp}; this file
// is purely presentation + state glue.

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

#include "vault.hpp"
#include "theme.hpp"
#include "pathutil.hpp"
#include "filedialog.hpp"
#include "generator.hpp"
#include "settings.hpp"
#include "version.hpp"

// Optional build-time customisation. A derived build can set these with compiler
// definitions: SV_APP_NAME / SV_LOGO_TEXT rename the app, SV_THEME_MAROON picks
// the alternative palette (theme.hpp), and SV_EXTRAS adds one extra tab drawn by
// extras.hpp (extras::kTabName, extras::Init(), extras::Draw()).
#ifndef SV_APP_NAME
#define SV_APP_NAME "Secure Vault"
#endif
#ifndef SV_SETTINGS_DIR
#define SV_SETTINGS_DIR "SecureVault"
#endif
#ifndef SV_LOGO_TEXT
#define SV_LOGO_TEXT "VAULT"
#endif
#ifdef SV_EXTRAS
#include "extras.hpp"
#endif

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <deque>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace {

enum class Mode { Text, File, Folder };

struct LogLine {
    std::string timestamp;
    std::string text;
    bool ok;
};

// Which part of the UI started the running job, so its result lands in the right place.
enum class Target { Home, Hash, Shred, Verify };

constexpr int kAutoLockMinutes[] = {0, 1, 5, 15, 30};  // 0 = off

struct AppState {
    // Navigation
    int activeTab = 0;  // 0 = Home, 1 = Log, 2 = Tools, 3 = Generate
    bool privateMode = false;  // masks the password field + log contents

    // Operation selection (Home tab)
    Mode mode = Mode::Text;
    bool encryptDirection = true;  // true = encrypt, false = decrypt

    char message[8192] = "";       // text mode input (plaintext or b64 payload)
    char path[1024] = "";          // file/folder path
    char password[256] = "";
    bool useKeyfile = false;
    char keyfilePath[1024] = "";

    char resultBuffer[16384] = "";  // last textual result (payload / decrypted text / messages)

    // Tools tab
    char hashPath[1024] = "";
    int hashAlgoIdx = 0;  // index into kHashAlgoNames
    char hashResult[256] = "";

    char shredPath[1024] = "";
    std::string shredStatus;
    bool shredOk = true;
    int shredPasses = 2;
    bool shredConfirmed = false;

    // Inspect / verify (Tools tab)
    char inspectPath[1024] = "";
    std::string inspectSummary;
    std::string verifyLine;
    bool verifyOk = true;

    // Generate tab
    int genMode = 0;  // 0 = password, 1 = passphrase
    generator::PasswordOptions genOpts;
    int genWords = 6;
    char genOutput[512] = "";
    std::string genNote;
    std::string keyfileMessage;
    bool keyfileOk = true;
    bool pendingKeyfile = false;

    // Clipboard auto-clear and idle auto-lock
    std::string clipboardCopied;
    double clipboardClearAt = 0.0;
    int autoLockIdx = 2;  // 5 minutes
    double lastActivity = 0.0;

    Target jobTarget = Target::Home;

    // A file or folder dropped on the window (filled by a GLFW callback, handled each frame).
    std::string pendingDrop;
    int pendingDropCount = 0;

    // Job + stats
    vault::VaultJob job;
    bool jobConsumed = true;
    int attempts = 0, successes = 0, failures = 0;
    uint64_t bytesProcessed = 0;

    std::deque<float> progressHistory;  // rolling sparkline of recent activity
    std::vector<LogLine> logLines;

    // A "Browse" click is recorded here and handled between frames, so the
    // blocking system dialog never opens in the middle of drawing the UI.
    char* browseTarget = nullptr;
    size_t browseCap = 0;
    filedialog::Kind browseKind = filedialog::Kind::OpenFile;

    std::thread worker;
};

const char* kHashAlgoNames[] = {"SHA-256", "SHA-512", "SHA-384", "SHA-1", "MD5"};
vault::HashAlgo kHashAlgoEnum[] = {vault::HashAlgo::SHA256, vault::HashAlgo::SHA512,
                                   vault::HashAlgo::SHA384, vault::HashAlgo::SHA1,
                                   vault::HashAlgo::MD5};

std::string NowString() {
    auto t = std::time(nullptr);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return buf;
}

void AddLog(AppState& app, const std::string& text, bool ok) {
    app.logLines.push_back({NowString(), text, ok});
    if (app.logLines.size() > 200) app.logLines.erase(app.logLines.begin());
}

// Overwrites a buffer in a way the compiler cannot optimise away.
void Wipe(void* p, size_t n) {
    volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
    while (n--) *v++ = 0;
}

std::vector<uint8_t> GetSecret(AppState& app) {
    if (app.useKeyfile) {
        std::ifstream f(pathutil::ToPath(pathutil::CleanPath(app.keyfilePath)), std::ios::binary);
        if (!f) throw std::runtime_error("Could not open key file.");
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                     std::istreambuf_iterator<char>());
    }
    std::string pw(app.password);
    return std::vector<uint8_t>(pw.begin(), pw.end());
}

bool JobBusy(AppState& app) { return app.job.running.load(); }

// Launches the currently-configured operation on a background thread.
void StartOperation(AppState& app) {
    if (JobBusy(app)) return;
    app.job.running = true;
    app.job.done = false;
    app.job.progress = 0.0f;
    app.jobConsumed = false;
    app.jobTarget = Target::Home;
    app.resultBuffer[0] = '\0';

    if (app.worker.joinable()) app.worker.join();

    Mode mode = app.mode;
    bool enc = app.encryptDirection;

    try {
        std::vector<uint8_t> secret = GetSecret(app);

        if (mode == Mode::Text) {
            // Text ops are effectively instant; still run off-thread for consistency.
            std::string input(app.message);
            app.worker = std::thread([&app, secret, input, enc]() {
                try {
                    std::string out = enc ? vault::EncryptText(secret, input)
                                           : vault::DecryptText(secret, input);
                    app.job.progress = 1.0f;
                    app.job.SetResult(true, out);
                } catch (const std::exception& e) {
                    app.job.SetResult(false, e.what());
                }
            });
        } else if (mode == Mode::File) {
            std::string inPath = pathutil::CleanPath(app.path);
            if (inPath.empty()) throw std::runtime_error("Enter a file path first.");
            std::string outPath = pathutil::FileOutputPath(inPath, enc);
            app.worker = std::thread([&app, secret, inPath, outPath, enc]() {
                using pathutil::ToPath;
                if (enc) vault::EncryptFile(secret, ToPath(inPath), ToPath(outPath), app.job);
                else     vault::DecryptFile(secret, ToPath(inPath), ToPath(outPath), app.job);
            });
        } else {  // Folder
            std::string inPath = pathutil::CleanPath(app.path);
            if (inPath.empty()) throw std::runtime_error("Enter a folder path first.");
            std::string outPath = pathutil::FolderOutputPath(inPath, enc);
            app.worker = std::thread([&app, secret, inPath, outPath, enc]() {
                using pathutil::ToPath;
                if (enc) vault::EncryptFolder(secret, ToPath(inPath), ToPath(outPath), app.job);
                else     vault::DecryptFolder(secret, ToPath(inPath), ToPath(outPath), app.job);
            });
        }
    } catch (const std::exception& e) {
        app.job.SetResult(false, e.what());
    }
}

void StartHash(AppState& app) {
    if (JobBusy(app)) return;
    app.job.running = true;
    app.job.done = false;
    app.job.progress = 0.0f;
    app.jobConsumed = false;
    app.jobTarget = Target::Hash;
    app.hashResult[0] = '\0';
    if (app.worker.joinable()) app.worker.join();

    std::string p = pathutil::CleanPath(app.hashPath);
    if (p.empty()) { app.job.SetResult(false, "Enter a file path first."); return; }
    vault::HashAlgo algo = kHashAlgoEnum[app.hashAlgoIdx];
    app.worker = std::thread([&app, p, algo]() {
        vault::HashFile(pathutil::ToPath(p), algo, app.job);
    });
}

void StartShred(AppState& app) {
    if (JobBusy(app) || !app.shredConfirmed) return;
    app.job.running = true;
    app.job.done = false;
    app.job.progress = 0.0f;
    app.jobConsumed = false;
    app.jobTarget = Target::Shred;
    app.shredStatus.clear();
    if (app.worker.joinable()) app.worker.join();

    std::string p = pathutil::CleanPath(app.shredPath);
    if (p.empty()) { app.job.SetResult(false, "Enter a file or folder path first."); return; }
    int passes = app.shredPasses;
    app.worker = std::thread([&app, p, passes]() {
        vault::ShredPath(pathutil::ToPath(p), passes, app.job);
    });
}

void StartVerify(AppState& app) {
    if (JobBusy(app)) return;
    app.job.running = true;
    app.job.done = false;
    app.job.progress = 0.0f;
    app.jobConsumed = false;
    app.jobTarget = Target::Verify;
    app.verifyLine.clear();
    if (app.worker.joinable()) app.worker.join();

    std::string p = pathutil::CleanPath(app.inspectPath);
    if (p.empty()) { app.job.SetResult(false, "Enter a file path first."); return; }
    try {
        std::vector<uint8_t> secret = GetSecret(app);
        app.worker = std::thread([&app, secret, p]() {
            vault::VerifyFile(secret, pathutil::ToPath(p), app.job);
        });
    } catch (const std::exception& e) {
        app.job.SetResult(false, e.what());
    }
}

// Pulls a finished job's result into the right place in app state + log/stats.
void PollJob(AppState& app) {
    if (app.job.done.load() && !app.jobConsumed) {
        std::lock_guard<std::mutex> lk(app.job.result_mutex);
        app.jobConsumed = true;
        app.attempts++;
        if (app.job.ok) app.successes++; else app.failures++;

        const char* label = "Operation";
        switch (app.jobTarget) {
            case Target::Home:   label = "Operation"; break;
            case Target::Hash:   label = "Hash"; break;
            case Target::Shred:  label = "Shred"; break;
            case Target::Verify: label = "Verify"; break;
        }
        AddLog(app, std::string(label) + ": " + app.job.result_text, app.job.ok);

        switch (app.jobTarget) {
            case Target::Home:
                std::snprintf(app.resultBuffer, sizeof(app.resultBuffer), "%s", app.job.result_text.c_str());
                break;
            case Target::Hash:
                std::snprintf(app.hashResult, sizeof(app.hashResult), "%s", app.job.result_text.c_str());
                break;
            case Target::Shred:
                app.shredStatus = app.job.result_text;
                app.shredOk = app.job.ok;
                break;
            case Target::Verify:
                app.verifyLine = app.job.result_text;
                app.verifyOk = app.job.ok;
                break;
        }
    }
    app.progressHistory.push_back(app.job.running ? app.job.progress.load()
                                                    : (app.progressHistory.empty() ? 0.0f
                                                                                   : app.progressHistory.back()));
    if (app.progressHistory.size() > 120) app.progressHistory.pop_front();
}

// Clears the password and any plaintext on screen after a period with no input.
void UpdateAutoLock(AppState& app, double now, bool activity) {
    if (activity || JobBusy(app)) { app.lastActivity = now; return; }
    int minutes = kAutoLockMinutes[app.autoLockIdx];
    if (minutes == 0 || now - app.lastActivity < minutes * 60.0) return;

    bool hadSecrets = app.password[0] || app.message[0] || app.resultBuffer[0] || app.genOutput[0];
    Wipe(app.password, sizeof(app.password));
    Wipe(app.message, sizeof(app.message));
    Wipe(app.resultBuffer, sizeof(app.resultBuffer));
    Wipe(app.genOutput, sizeof(app.genOutput));
    if (!app.clipboardCopied.empty()) app.clipboardClearAt = 0.0;  // clear the clipboard right away
    app.lastActivity = now;
    if (hadSecrets)
        AddLog(app, "Auto-locked after " + std::to_string(minutes) + " min idle: password and text cleared.", true);
}

// ---------------------------------------------------------------------
// Small UI helpers
// ---------------------------------------------------------------------

bool BeginCard(const char* id, ImVec2 size, const char* title) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kCard);
    ImGui::PushStyleColor(ImGuiCol_Border, theme::kCardBorder);
    bool open = ImGui::BeginChild(id, size, true, ImGuiWindowFlags_NoScrollbar);
    if (open && title) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
        ImGui::TextUnformatted(title);
        ImGui::PopStyleColor();
        ImGui::Spacing();
    }
    return open;
}
void EndCard() {
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
}

void StatusDot(bool ok, const char* text) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImU32 col = ImGui::ColorConvertFloat4ToU32(ok ? theme::kGreen : theme::kRed);
    dl->AddCircleFilled(ImVec2(p.x + 6, p.y + 10), 6.0f, col);
    ImGui::Dummy(ImVec2(18, 0));
    ImGui::SameLine();
    ImGui::TextUnformatted(text);
}

void PillButton(const char* label, bool active, const ImVec2& size = ImVec2(0, 0)) {
    if (active) {
        ImGui::PushStyleColor(ImGuiCol_Button, theme::kPink);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, theme::kPink);
    }
    ImGui::Button(label, size);
    if (active) ImGui::PopStyleColor(2);
}

// A path text box with Browse button(s) on the same row. A path pasted with
// surrounding quotes (Windows "Copy as path") has them removed right away.
// Never use this for passwords.
void PathRow(AppState& app, const char* id, char* buf, size_t cap, bool allowFile,
             bool allowFolder) {
    const float sp = ImGui::GetStyle().ItemSpacing.x;
    const bool both = allowFile && allowFolder;
    const float total = both ? (60.0f + 70.0f + 2 * sp) : (90.0f + sp);

    ImGui::SetNextItemWidth(-total);
    if (ImGui::InputText(id, buf, cap)) pathutil::StripQuotesInPlace(buf, cap);
    ImGui::SameLine();

    auto request = [&](filedialog::Kind kind) {
        app.browseTarget = buf;
        app.browseCap = cap;
        app.browseKind = kind;
    };
    ImGui::PushID(id);
    if (both) {
        if (ImGui::Button("File", ImVec2(60, 0))) request(filedialog::Kind::OpenFile);
        ImGui::SameLine();
        if (ImGui::Button("Folder", ImVec2(70, 0))) request(filedialog::Kind::PickFolder);
    } else if (ImGui::Button("Browse", ImVec2(90, 0))) {
        request(allowFolder ? filedialog::Kind::PickFolder : filedialog::Kind::OpenFile);
    }
    ImGui::PopID();
}

// Dropping a file or folder on the window fills in the relevant path box:
//   Home tab:  the operation path (and the mode, and encrypt/decrypt, are chosen to match)
//   Tools tab: an .enc file goes to Inspect / Verify, any other file to Hash
void HandleDrop(AppState& app, const std::string& dropped, int count) {
    std::error_code ec;
    const std::string p = pathutil::CleanPath(dropped);
    const bool isDir = std::filesystem::is_directory(pathutil::ToPath(p), ec);
    const bool isEnc = pathutil::EndsWith(p, ".enc");
    const std::string extra = count > 1 ? " (only the first of " + std::to_string(count) + " items was used)" : "";

    if (app.activeTab == 0) {
        std::snprintf(app.path, sizeof(app.path), "%s", p.c_str());
        if (isDir) { app.mode = Mode::Folder; app.encryptDirection = true; }
        else if (pathutil::EndsWith(p, "_folder.enc")) { app.mode = Mode::Folder; app.encryptDirection = false; }
        else { app.mode = Mode::File; app.encryptDirection = !isEnc; }
        AddLog(app, "Dropped: " + p + extra, true);
    } else if (app.activeTab == 2) {
        if (isDir) { AddLog(app, "Drop a file on the Tools tab, not a folder.", false); return; }
        char* target = isEnc ? app.inspectPath : app.hashPath;
        size_t cap = isEnc ? sizeof(app.inspectPath) : sizeof(app.hashPath);
        std::snprintf(target, cap, "%s", p.c_str());
        AddLog(app, std::string("Dropped for ") + (isEnc ? "Inspect / Verify: " : "Hash: ") + p + extra, true);
    }
}

AppState* g_dropTarget = nullptr;

void DropCallback(GLFWwindow*, int count, const char** paths) {
    if (g_dropTarget && count > 0 && paths && paths[0]) {
        g_dropTarget->pendingDrop = paths[0];  // GLFW delivers UTF-8
        g_dropTarget->pendingDropCount = count;
    }
}

settings::Ui SnapshotSettings(const AppState& a) {
    settings::Ui u;
    u.autoLockIdx = a.autoLockIdx;
    u.privateMode = a.privateMode;
    u.hashAlgoIdx = a.hashAlgoIdx;
    u.shredPasses = a.shredPasses;
    u.genMode = a.genMode;
    u.genLength = a.genOpts.length;
    u.genLower = a.genOpts.lower;
    u.genUpper = a.genOpts.upper;
    u.genDigits = a.genOpts.digits;
    u.genSymbols = a.genOpts.symbols;
    u.genWords = a.genWords;
    return u;
}

void ApplySettings(AppState& a, const settings::Ui& u) {
    a.autoLockIdx = u.autoLockIdx;
    a.privateMode = u.privateMode;
    a.hashAlgoIdx = u.hashAlgoIdx;
    a.shredPasses = u.shredPasses;
    a.genMode = u.genMode;
    a.genOpts.length = u.genLength;
    a.genOpts.lower = u.genLower;
    a.genOpts.upper = u.genUpper;
    a.genOpts.digits = u.genDigits;
    a.genOpts.symbols = u.genSymbols;
    a.genWords = u.genWords;
}

}  // namespace

// ---------------------------------------------------------------------
// GLFW error callback
// ---------------------------------------------------------------------
static void GlfwErrorCallback(int error, const char* desc) {
    std::fprintf(stderr, "GLFW error %d: %s\n", error, desc);
}

int main() {
    glfwSetErrorCallback(GlfwErrorCallback);
    if (!glfwInit()) return 1;

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1180, 760, SV_APP_NAME " " SV_VERSION, nullptr, nullptr);
    if (!window) { glfwTerminate(); return 1; }
    glfwMakeContextCurrent(window);
    filedialog::SetOwner(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    theme::Apply(ImGui::GetStyle());

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    AppState app;
    const auto settingsPath = settings::FilePath(SV_SETTINGS_DIR);
    settings::Ui lastSaved = settings::Load(settingsPath);
    ApplySettings(app, lastSaved);
    g_dropTarget = &app;
    glfwSetDropCallback(window, DropCallback);
    AddLog(app, SV_APP_NAME " " SV_VERSION " initialized. AES-256-GCM / PBKDF2-HMAC-SHA256 (600k).", true);
#ifdef SV_EXTRAS
    extras::Init();
#endif

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        if (!app.pendingDrop.empty()) {
            HandleDrop(app, app.pendingDrop, app.pendingDropCount);
            app.pendingDrop.clear();
            app.lastActivity = glfwGetTime();  // a drop counts as activity for auto-lock
        }

        // Handle a pending Browse click here, outside of any ImGui frame.
        if (app.browseTarget) {
            std::string picked;
            if (filedialog::Browse(app.browseKind, picked)) {
                picked = pathutil::CleanPath(picked);
                std::snprintf(app.browseTarget, app.browseCap, "%s", picked.c_str());
            }
            app.browseTarget = nullptr;
        }

        if (app.pendingKeyfile) {
            app.pendingKeyfile = false;
            std::string picked;
            if (filedialog::Browse(filedialog::Kind::SaveFile, picked)) {
                picked = pathutil::CleanPath(picked);
                std::string err;
                if (generator::WriteKeyFile(pathutil::ToPath(picked), generator::kKeyFileBytes, err)) {
                    std::snprintf(app.keyfilePath, sizeof(app.keyfilePath), "%s", picked.c_str());
                    app.useKeyfile = true;
                    app.keyfileOk = true;
                    app.keyfileMessage = "Created and selected on the Home tab: " + picked;
                    AddLog(app, "Created key file " + picked, true);
                } else {
                    app.keyfileOk = false;
                    app.keyfileMessage = "Could not create the key file: " + err;
                }
            }
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        {
            const double now = glfwGetTime();

            // Clear the clipboard 30 seconds after a generated password was copied,
            // but only if it still holds that password (don't wipe something newer).
            if (!app.clipboardCopied.empty() && now >= app.clipboardClearAt) {
                const char* cur = ImGui::GetClipboardText();
                if (cur && app.clipboardCopied == cur) ImGui::SetClipboardText("");
                app.clipboardCopied.clear();
            }

            bool activity = io.MouseDelta.x != 0.0f || io.MouseDelta.y != 0.0f || io.MouseWheel != 0.0f ||
                            io.InputQueueCharacters.Size > 0 ||
                            ImGui::IsMouseClicked(ImGuiMouseButton_Left) ||
                            ImGui::IsMouseClicked(ImGuiMouseButton_Right) ||
                            ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_Backspace) ||
                            ImGui::IsKeyPressed(ImGuiKey_Delete) || ImGui::IsKeyPressed(ImGuiKey_Tab) ||
                            ImGui::IsKeyPressed(ImGuiKey_LeftArrow) || ImGui::IsKeyPressed(ImGuiKey_RightArrow) ||
                            ImGui::IsKeyPressed(ImGuiKey_UpArrow) || ImGui::IsKeyPressed(ImGuiKey_DownArrow);
            UpdateAutoLock(app, now, activity);

            // Remember preferences. Wait for the mouse to be released so dragging a
            // slider does not write the file on every frame.
            settings::Ui current = SnapshotSettings(app);
            if (!(current == lastSaved) && !ImGui::IsAnyMouseDown()) {
                settings::Save(settingsPath, current);
                lastSaved = current;
            }
        }

        // F9 toggles the window's title bar and border (handy for clean screenshots).
        // F9 rather than F10, because Windows treats F10 as a menu key.
        if (ImGui::IsKeyPressed(ImGuiKey_F9, false)) {
            static bool decorated = true;
            decorated = !decorated;
            glfwSetWindowAttrib(window, GLFW_DECORATED, decorated ? GLFW_TRUE : GLFW_FALSE);
        }

        PollJob(app);

        ImGuiViewport* vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(vp->WorkPos);
        ImGui::SetNextWindowSize(vp->WorkSize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        ImGui::Begin("##root", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                         ImGuiWindowFlags_NoBringToFrontOnFocus);
        ImGui::PopStyleVar();

        theme::DrawBackdrop(ImGui::GetWindowDrawList(), vp->WorkSize);

        // ---------------- Top bar ----------------
        {
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 p = ImGui::GetCursorScreenPos();
            theme::DrawFlower(dl, ImVec2(p.x + 20, p.y + 18), 16.0f,
                               ImGui::ColorConvertFloat4ToU32(theme::kPinkSoft),
                               ImGui::ColorConvertFloat4ToU32(theme::kPink));
            ImGui::Dummy(ImVec2(44, 0));
            ImGui::SameLine();
            ImGui::SetWindowFontScale(1.6f);
            ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextBright);
            ImGui::TextUnformatted(SV_LOGO_TEXT);
            ImGui::PopStyleColor();
            ImGui::SetWindowFontScale(1.0f);

            ImGui::SameLine(0, 40);
            std::vector<const char*> tabs = {"Home", "Log", "Tools", "Generate"};
#ifdef SV_EXTRAS
            tabs.push_back(extras::kTabName);
#endif
            for (int i = 0; i < (int)tabs.size(); i++) {
                ImGui::PushID(i);
                if (app.activeTab == i) ImGui::PushStyleColor(ImGuiCol_Text, theme::kPink);
                else ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
                if (ImGui::Button(tabs[i], ImVec2(82, 28))) app.activeTab = i;
                ImGui::PopStyleColor();
                ImGui::SameLine();
                ImGui::PopID();
            }

            float rightEdge = vp->WorkSize.x - 400;
            ImGui::SameLine(rightEdge);
            {
                int mins = kAutoLockMinutes[app.autoLockIdx];
                std::string label = mins == 0 ? "AUTO-LOCK: OFF" : "AUTO-LOCK: " + std::to_string(mins) + " MIN";
                PillButton((label + "##autolock").c_str(), mins != 0, ImVec2(160, 28));
                if (ImGui::IsItemClicked())
                    app.autoLockIdx = (app.autoLockIdx + 1) % (int)IM_ARRAYSIZE(kAutoLockMinutes);
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Clears the password and any text on screen after this much idle time. Click to change.");
                ImGui::SameLine();
            }
            PillButton(app.privateMode ? "PRIVATE: ON" : "PRIVATE: OFF", app.privateMode,
                       ImVec2(140, 28));
            if (ImGui::IsItemClicked()) app.privateMode = !app.privateMode;
            ImGui::SameLine();
            bool busy = JobBusy(app);
            ImGui::PushStyleColor(ImGuiCol_Text, busy ? theme::kGold : theme::kGreen);
            ImGui::Text(busy ? "RUNNING" : "READY");
            ImGui::PopStyleColor();
        }
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImVec2 avail = ImGui::GetContentRegionAvail();
        float rowH = (avail.y - 24) * 0.58f;
        float row2H = (avail.y - 24) * 0.42f - 10;

        if (app.activeTab == 0) {
            // ---------------- HOME: operation card (left, tall) ----------------
            float leftW = avail.x * 0.42f;
            if (BeginCard("opcard", ImVec2(leftW, rowH), "OPERATION")) {
                const char* modeName[] = {"TEXT", "FILE", "FOLDER"};
                ImGui::SetWindowFontScale(1.8f);
                ImGui::PushStyleColor(ImGuiCol_Text, theme::kPink);
                ImGui::Text("%s %s", app.encryptDirection ? "ENCRYPT" : "DECRYPT", modeName[(int)app.mode]);
                ImGui::PopStyleColor();
                ImGui::SetWindowFontScale(1.0f);
                ImGui::Spacing();

                PillButton("TEXT", app.mode == Mode::Text, ImVec2(70, 26));
                if (ImGui::IsItemClicked()) app.mode = Mode::Text;
                ImGui::SameLine();
                PillButton("FILE", app.mode == Mode::File, ImVec2(70, 26));
                if (ImGui::IsItemClicked()) app.mode = Mode::File;
                ImGui::SameLine();
                PillButton("FOLDER", app.mode == Mode::Folder, ImVec2(80, 26));
                if (ImGui::IsItemClicked()) app.mode = Mode::Folder;
                ImGui::SameLine(0, 24);
                PillButton("ENCRYPT", app.encryptDirection, ImVec2(80, 26));
                if (ImGui::IsItemClicked()) app.encryptDirection = true;
                ImGui::SameLine();
                PillButton("DECRYPT", !app.encryptDirection, ImVec2(80, 26));
                if (ImGui::IsItemClicked()) app.encryptDirection = false;

                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                if (app.mode == Mode::Text) {
                    ImGui::TextColored(theme::kTextDim, app.encryptDirection
                                            ? "Message to encrypt"
                                            : "Encrypted payload (base64)");
                    ImGui::InputTextMultiline("##msg", app.message, sizeof(app.message),
                                               ImVec2(-1, 90));
                } else {
                    ImGui::TextColored(theme::kTextDim, app.mode == Mode::File
                                            ? "File path" : "Folder path");
                    // Encrypting a folder picks a folder; everything else picks a file
                    // (decrypting a folder starts from its .enc file).
                    bool pickFolder = app.mode == Mode::Folder && app.encryptDirection;
                    PathRow(app, "##path", app.path, sizeof(app.path), !pickFolder, pickFolder);
                }

                ImGui::Spacing();
                ImGui::TextColored(theme::kTextDim, "Authentication");
                ImGui::Checkbox("Use key file instead of password", &app.useKeyfile);
                if (app.useKeyfile) {
                    PathRow(app, "##keyfile", app.keyfilePath, sizeof(app.keyfilePath), true, false);
                } else {
                    ImGui::SetNextItemWidth(-1);
                    ImGuiInputTextFlags pwFlags =
                        app.privateMode ? ImGuiInputTextFlags_Password : 0;
                    ImGui::InputText("##pw", app.password, sizeof(app.password), pwFlags);
                }

                ImGui::Spacing();
                bool busy = JobBusy(app);
                ImGui::BeginDisabled(busy);
                if (ImGui::Button(busy ? "WORKING..." : "START", ImVec2(140, 36))) {
                    StartOperation(app);
                }
                ImGui::EndDisabled();
                ImGui::SameLine();
                ImGui::ProgressBar(app.job.progress.load(), ImVec2(-1, 20));
            }
            EndCard();

            ImGui::SameLine();

            // ---------------- HOME: right column, top row ----------------
            float rightW = avail.x - leftW - ImGui::GetStyle().ItemSpacing.x;
            float rCardH = (rowH - ImGui::GetStyle().ItemSpacing.y) * 0.5f;
            if (BeginCard("statuscard", ImVec2(rightW, rCardH), "STATUS")) {
                bool busy = JobBusy(app);
                StatusDot(!busy, busy ? "Operation running..." : "Idle - ready for input");
                ImGui::Spacing();
                ImGui::TextColored(theme::kTextDim, "Cipher");
                ImGui::Text("AES-256-GCM, file format v2");
                ImGui::TextColored(theme::kTextDim, "Key derivation");
                ImGui::Text("PBKDF2-HMAC-SHA256, 600,000 rounds");
            }
            EndCard();

            ImGui::Dummy(ImVec2(leftW + ImGui::GetStyle().ItemSpacing.x, 0));
            ImGui::SameLine();
            if (BeginCard("resultcard", ImVec2(rightW, rCardH), "RESULT")) {
                if (app.privateMode && app.mode == Mode::Text) {
                    ImGui::TextColored(theme::kTextDim, "(hidden in Private mode)");
                } else {
                    ImGui::InputTextMultiline("##result", app.resultBuffer,
                                               sizeof(app.resultBuffer), ImVec2(-1, -1),
                                               ImGuiInputTextFlags_ReadOnly);
                }
            }
            EndCard();

            // ---------------- HOME: bottom row ----------------
            float bLeftW = avail.x * 0.42f;
            float bRightW = avail.x - bLeftW - ImGui::GetStyle().ItemSpacing.x;
            if (BeginCard("activitycard", ImVec2(bLeftW, row2H), "ACTIVITY")) {
                ImGui::SetWindowFontScale(2.2f);
                ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextBright);
                ImGui::Text("%d", app.attempts);
                ImGui::PopStyleColor();
                ImGui::SetWindowFontScale(1.0f);
                ImGui::SameLine();
                ImGui::TextColored(theme::kTextDim, "  operations run");

                std::vector<float> hist(app.progressHistory.begin(), app.progressHistory.end());
                if (hist.empty()) hist.push_back(0.0f);
                ImGui::PlotLines("##hist", hist.data(), (int)hist.size(), 0, nullptr, 0.0f, 1.0f,
                                  ImVec2(-1, 60));
            }
            EndCard();

            ImGui::SameLine();
            if (BeginCard("statscard", ImVec2(bRightW, row2H), "STATISTICS")) {
                ImGui::Columns(2, nullptr, false);
                ImGui::TextColored(theme::kTextDim, "ATTEMPTS");
                ImGui::Text("%d", app.attempts);
                ImGui::NextColumn();
                ImGui::TextColored(theme::kTextDim, "FAILURES");
                ImGui::Text("%d", app.failures);
                ImGui::NextColumn();
                ImGui::Spacing(); ImGui::Spacing();
                ImGui::NextColumn();
                ImGui::Spacing(); ImGui::Spacing();
                ImGui::NextColumn();
                ImGui::TextColored(theme::kTextDim, "SUCCESSES");
                ImGui::Text("%d", app.successes);
                ImGui::NextColumn();
                ImGui::TextColored(theme::kTextDim, "SUCCESS RATE");
                ImGui::Text("%.0f%%", app.attempts > 0
                                           ? 100.0f * (float)app.successes / (float)app.attempts
                                           : 0.0f);
                ImGui::Columns(1);
            }
            EndCard();

        } else if (app.activeTab == 1) {
            // ---------------- LOG ----------------
            if (BeginCard("logcard", ImVec2(avail.x, avail.y), "ACTIVITY LOG")) {
                if (app.privateMode) {
                    ImGui::TextColored(theme::kTextDim, "Log hidden while Private mode is on.");
                } else {
                    for (auto it = app.logLines.rbegin(); it != app.logLines.rend(); ++it) {
                        ImGui::TextColored(theme::kTextDim, "[%s]", it->timestamp.c_str());
                        ImGui::SameLine();
                        ImGui::PushStyleColor(ImGuiCol_Text, it->ok ? theme::kGreen : theme::kRed);
                        ImGui::TextWrapped("%s", it->text.c_str());
                        ImGui::PopStyleColor();
                    }
                }
            }
            EndCard();

        } else if (app.activeTab == 2) {
            // ---------------- TOOLS: Hash + Shred (top), Inspect / Verify (bottom) ----------------
            float toolsRowH = (avail.y - ImGui::GetStyle().ItemSpacing.y) * 0.52f;
            float inspectH = avail.y - toolsRowH - ImGui::GetStyle().ItemSpacing.y;
            float w = (avail.x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
            if (BeginCard("hashcard", ImVec2(w, toolsRowH), "HASH A FILE")) {
                ImGui::TextColored(theme::kTextDim, "File path");
                PathRow(app, "##hashpath", app.hashPath, sizeof(app.hashPath), true, false);
                ImGui::SetNextItemWidth(220);
                ImGui::Combo("##algo", &app.hashAlgoIdx, kHashAlgoNames,
                             IM_ARRAYSIZE(kHashAlgoNames));
                ImGui::SameLine();
                bool busy = JobBusy(app);
                ImGui::BeginDisabled(busy);
                if (ImGui::Button("COMPUTE", ImVec2(120, 0))) StartHash(app);
                ImGui::EndDisabled();
                ImGui::Spacing();
                ImGui::ProgressBar(app.job.progress.load(), ImVec2(-1, 18));
                ImGui::Spacing();
                ImGui::TextColored(theme::kTextDim, "Digest");
                ImGui::InputText("##hashresult", app.hashResult, sizeof(app.hashResult),
                                  ImGuiInputTextFlags_ReadOnly);
            }
            EndCard();

            ImGui::SameLine();
            if (BeginCard("shredcard", ImVec2(w, toolsRowH), "SECURE SHRED")) {
                ImGui::TextColored(theme::kRed, "Permanently destroys the target - cannot be undone.");
                ImGui::TextColored(theme::kTextDim, "File or folder path");
                PathRow(app, "##shredpath", app.shredPath, sizeof(app.shredPath), true, true);
                ImGui::SetNextItemWidth(160);
                ImGui::SliderInt("passes", &app.shredPasses, 1, 5);
                ImGui::Checkbox("I understand this is irreversible", &app.shredConfirmed);
                bool busy = JobBusy(app);
                ImGui::BeginDisabled(busy || !app.shredConfirmed);
                ImGui::PushStyleColor(ImGuiCol_Button, theme::kRed);
                if (ImGui::Button("SHRED NOW", ImVec2(140, 0))) StartShred(app);
                ImGui::PopStyleColor();
                ImGui::EndDisabled();
                ImGui::SameLine();
                ImGui::ProgressBar(app.job.progress.load(), ImVec2(-1, 0));
                if (!app.shredStatus.empty())
                    ImGui::TextColored(app.shredOk ? theme::kGreen : theme::kRed, "%s", app.shredStatus.c_str());
            }
            EndCard();

            if (BeginCard("inspectcard", ImVec2(avail.x, inspectH), "INSPECT / VERIFY AN ENCRYPTED FILE")) {
                ImGui::Columns(2, nullptr, false);
                ImGui::SetColumnWidth(0, avail.x * 0.55f);

                ImGui::TextColored(theme::kTextDim, "Encrypted file");
                PathRow(app, "##inspectpath", app.inspectPath, sizeof(app.inspectPath), true, false);
                ImGui::Checkbox("Use key file instead of password##inspect", &app.useKeyfile);
                if (app.useKeyfile) {
                    PathRow(app, "##inspectkey", app.keyfilePath, sizeof(app.keyfilePath), true, false);
                } else {
                    ImGui::SetNextItemWidth(-1);
                    ImGui::InputText("##inspectpw", app.password, sizeof(app.password),
                                     app.privateMode ? ImGuiInputTextFlags_Password : 0);
                }
                bool busy = JobBusy(app);
                if (ImGui::Button("INSPECT", ImVec2(110, 0))) {
                    std::string p = pathutil::CleanPath(app.inspectPath);
                    app.verifyLine.clear();
                    app.inspectSummary = p.empty() ? "Enter a file path first."
                                                   : vault::InspectFile(pathutil::ToPath(p)).summary;
                }
                ImGui::SameLine();
                ImGui::BeginDisabled(busy);
                if (ImGui::Button("VERIFY", ImVec2(110, 0))) StartVerify(app);
                ImGui::EndDisabled();
                ImGui::SameLine();
                ImGui::ProgressBar(app.job.progress.load(), ImVec2(-1, 0));
                ImGui::TextColored(theme::kTextDim, "Inspect needs no password. Verify checks every chunk.");

                ImGui::NextColumn();
                ImGui::BeginChild("inspectout", ImVec2(-1, -1), false);
                if (!app.inspectSummary.empty()) ImGui::TextWrapped("%s", app.inspectSummary.c_str());
                if (!app.verifyLine.empty()) {
                    ImGui::Spacing();
                    ImGui::TextColored(app.verifyOk ? theme::kGreen : theme::kRed, "%s", app.verifyLine.c_str());
                }
                ImGui::EndChild();
                ImGui::Columns(1);
            }
            EndCard();

        } else if (app.activeTab == 3) {
            // ---------------- GENERATE: passwords / passphrases, key files ----------------
            float w = (avail.x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
            if (BeginCard("gencard", ImVec2(w, avail.y), "PASSWORD GENERATOR")) {
                PillButton("PASSWORD", app.genMode == 0, ImVec2(110, 26));
                if (ImGui::IsItemClicked()) app.genMode = 0;
                ImGui::SameLine();
                PillButton("PASSPHRASE", app.genMode == 1, ImVec2(120, 26));
                if (ImGui::IsItemClicked()) app.genMode = 1;
                ImGui::Spacing();

                double bits = 0.0;
                if (app.genMode == 0) {
                    ImGui::SetNextItemWidth(220);
                    ImGui::SliderInt("length", &app.genOpts.length, generator::kMinPasswordLength, 64);
                    ImGui::Checkbox("a-z", &app.genOpts.lower);
                    ImGui::SameLine();
                    ImGui::Checkbox("A-Z", &app.genOpts.upper);
                    ImGui::SameLine();
                    ImGui::Checkbox("0-9", &app.genOpts.digits);
                    ImGui::SameLine();
                    ImGui::Checkbox("symbols", &app.genOpts.symbols);
                    bits = generator::PasswordBits(app.genOpts);
                } else {
                    ImGui::SetNextItemWidth(220);
                    ImGui::SliderInt("words", &app.genWords, generator::kMinWords, 12);
                    ImGui::TextColored(theme::kTextDim, "Random words from a 2048-word list, joined with dashes.");
                    bits = generator::PassphraseBits(app.genWords);
                }

                ImGui::Spacing();
                if (ImGui::Button("GENERATE", ImVec2(140, 34))) {
                    try {
                        std::string out = app.genMode == 0 ? generator::GeneratePassword(app.genOpts)
                                                           : generator::GeneratePassphrase(app.genWords);
                        std::snprintf(app.genOutput, sizeof(app.genOutput), "%s", out.c_str());
                        Wipe(&out[0], out.size());
                        app.genNote.clear();
                    } catch (const std::exception& e) {
                        app.genNote = e.what();
                    }
                }

                ImGui::SetNextItemWidth(-1);
                ImGui::InputText("##genout", app.genOutput, sizeof(app.genOutput),
                                 ImGuiInputTextFlags_ReadOnly |
                                     (app.privateMode ? ImGuiInputTextFlags_Password : 0));
                const char* rating = bits >= 80 ? "strong" : bits >= 60 ? "good" : "weak";
                ImGui::TextColored(theme::kTextDim, "About %.0f bits of entropy (%s)", bits, rating);
                if (!app.genNote.empty()) ImGui::TextColored(theme::kRed, "%s", app.genNote.c_str());

                ImGui::Spacing();
                ImGui::BeginDisabled(app.genOutput[0] == '\0');
                if (ImGui::Button("COPY", ImVec2(100, 0))) {
                    ImGui::SetClipboardText(app.genOutput);
                    app.clipboardCopied = app.genOutput;
                    app.clipboardClearAt = glfwGetTime() + 30.0;
                    app.genNote = "Copied. The clipboard is cleared in 30 seconds.";
                }
                ImGui::SameLine();
                if (ImGui::Button("USE AS PASSWORD", ImVec2(170, 0))) {
                    std::snprintf(app.password, sizeof(app.password), "%s", app.genOutput);
                    app.useKeyfile = false;
                    app.genNote = "Set as the password on the Home tab. Save it somewhere safe: it is not stored.";
                }
                ImGui::EndDisabled();
                ImGui::TextColored(theme::kTextDim,
                                   "Clipboard history tools (such as Win+V) may keep their own copy.");
            }
            EndCard();

            ImGui::SameLine();
            if (BeginCard("keycard", ImVec2(w, avail.y), "KEY FILE")) {
                ImGui::TextWrapped(
                    "A key file is a random 64-byte file you use instead of a password. "
                    "Anyone who has the file can open what it protects, and if you lose it, "
                    "everything encrypted with it is gone for good.");
                ImGui::Spacing();
                ImGui::TextColored(theme::kGold, "Keep a backup somewhere safe, and keep it private.");
                ImGui::Spacing();
                if (ImGui::Button("CREATE KEY FILE...", ImVec2(220, 36))) app.pendingKeyfile = true;
                if (!app.keyfileMessage.empty()) {
                    ImGui::Spacing();
                    ImGui::TextColored(app.keyfileOk ? theme::kGreen : theme::kRed, "%s",
                                       app.keyfileMessage.c_str());
                }
            }
            EndCard();
        }
#ifdef SV_EXTRAS
        else if (app.activeTab == 4) {
            extras::Draw(avail.x, avail.y);
        }
#endif

        ImGui::End();  // ##root

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.05f, 0.02f, 0.05f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    if (app.worker.joinable()) app.worker.join();

#ifdef SV_EXTRAS
    extras::Shutdown();
#endif

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
