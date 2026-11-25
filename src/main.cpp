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

struct AppState {
    // Navigation
    int activeTab = 0;  // 0 = Home, 1 = Log, 2 = Tools
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
    int shredPasses = 2;
    bool shredConfirmed = false;

    // Job + stats
    vault::VaultJob job;
    bool jobConsumed = true;
    int attempts = 0, successes = 0, failures = 0;
    uint64_t bytesProcessed = 0;

    std::deque<float> progressHistory;  // rolling sparkline of recent activity
    std::vector<LogLine> logLines;

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

std::vector<uint8_t> GetSecret(AppState& app) {
    if (app.useKeyfile) {
        std::ifstream f(app.keyfilePath, std::ios::binary);
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
            std::string inPath(app.path);
            std::string outPath = enc ? inPath + ".enc"
                                       : (inPath.size() > 4 && inPath.substr(inPath.size() - 4) == ".enc"
                                              ? inPath.substr(0, inPath.size() - 4)
                                              : inPath + ".decrypted");
            app.worker = std::thread([&app, secret, inPath, outPath, enc]() {
                if (enc) vault::EncryptFile(secret, inPath, outPath, app.job);
                else     vault::DecryptFile(secret, inPath, outPath, app.job);
            });
        } else {  // Folder
            std::string inPath(app.path);
            std::string outPath;
            if (enc) {
                std::string clean = inPath;
                while (!clean.empty() && (clean.back() == '/' || clean.back() == '\\'))
                    clean.pop_back();
                outPath = clean + "_folder.enc";
            } else {
                if (inPath.size() > 11 && inPath.substr(inPath.size() - 11) == "_folder.enc")
                    outPath = inPath.substr(0, inPath.size() - 11) + "_restored";
                else if (inPath.size() > 4 && inPath.substr(inPath.size() - 4) == ".enc")
                    outPath = inPath.substr(0, inPath.size() - 4) + "_restored";
                else
                    outPath = inPath + "_restored";
            }
            app.worker = std::thread([&app, secret, inPath, outPath, enc]() {
                if (enc) vault::EncryptFolder(secret, inPath, outPath, app.job);
                else     vault::DecryptFolder(secret, inPath, outPath, app.job);
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
    app.hashResult[0] = '\0';
    if (app.worker.joinable()) app.worker.join();

    std::string p(app.hashPath);
    vault::HashAlgo algo = kHashAlgoEnum[app.hashAlgoIdx];
    app.worker = std::thread([&app, p, algo]() { vault::HashFile(p, algo, app.job); });
}

void StartShred(AppState& app) {
    if (JobBusy(app) || !app.shredConfirmed) return;
    app.job.running = true;
    app.job.done = false;
    app.job.progress = 0.0f;
    app.jobConsumed = false;
    if (app.worker.joinable()) app.worker.join();

    std::string p(app.shredPath);
    int passes = app.shredPasses;
    app.worker = std::thread([&app, p, passes]() { vault::ShredPath(p, passes, app.job); });
}

// Pulls a finished job's result into the right place in app state + log/stats.
void PollJob(AppState& app, const char* opLabel) {
    if (app.job.done.load() && !app.jobConsumed) {
        std::lock_guard<std::mutex> lk(app.job.result_mutex);
        app.jobConsumed = true;
        app.attempts++;
        if (app.job.ok) app.successes++; else app.failures++;

        AddLog(app, std::string(opLabel) + ": " + app.job.result_text, app.job.ok);

        if (app.activeTab == 2 && opLabel == std::string("Hash")) {
            std::snprintf(app.hashResult, sizeof(app.hashResult), "%s", app.job.result_text.c_str());
        } else {
            std::snprintf(app.resultBuffer, sizeof(app.resultBuffer), "%s", app.job.result_text.c_str());
        }
    }
    app.progressHistory.push_back(app.job.running ? app.job.progress.load()
                                                    : (app.progressHistory.empty() ? 0.0f
                                                                                   : app.progressHistory.back()));
    if (app.progressHistory.size() > 120) app.progressHistory.pop_front();
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

    GLFWwindow* window = glfwCreateWindow(1180, 760, "Secure Vault", nullptr, nullptr);
    if (!window) { glfwTerminate(); return 1; }
    glfwMakeContextCurrent(window);
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
    AddLog(app, "Secure Vault initialized. AES-256-GCM / PBKDF2-HMAC-SHA256 (600k).", true);

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        PollJob(app, app.activeTab == 2 ? "Hash/Shred" : "Operation");

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
            ImGui::TextUnformatted("VAULT");
            ImGui::PopStyleColor();
            ImGui::SetWindowFontScale(1.0f);

            ImGui::SameLine(0, 40);
            const char* tabs[] = {"Home", "Log", "Tools"};
            for (int i = 0; i < 3; i++) {
                ImGui::PushID(i);
                if (app.activeTab == i) ImGui::PushStyleColor(ImGuiCol_Text, theme::kPink);
                else ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
                if (ImGui::Button(tabs[i], ImVec2(70, 28))) app.activeTab = i;
                ImGui::PopStyleColor();
                ImGui::SameLine();
                ImGui::PopID();
            }

            float rightEdge = vp->WorkSize.x - 230;
            ImGui::SameLine(rightEdge);
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
                    ImGui::SetNextItemWidth(-1);
                    ImGui::InputText("##path", app.path, sizeof(app.path));
                }

                ImGui::Spacing();
                ImGui::TextColored(theme::kTextDim, "Authentication");
                ImGui::Checkbox("Use key file instead of password", &app.useKeyfile);
                if (app.useKeyfile) {
                    ImGui::SetNextItemWidth(-1);
                    ImGui::InputText("##keyfile", app.keyfilePath, sizeof(app.keyfilePath));
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
                ImGui::Text("AES-256-GCM");
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

        } else {
            // ---------------- TOOLS: Hash + Shred ----------------
            float w = (avail.x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
            if (BeginCard("hashcard", ImVec2(w, avail.y), "HASH A FILE")) {
                ImGui::TextColored(theme::kTextDim, "File path");
                ImGui::SetNextItemWidth(-1);
                ImGui::InputText("##hashpath", app.hashPath, sizeof(app.hashPath));
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
            if (BeginCard("shredcard", ImVec2(w, avail.y), "SECURE SHRED")) {
                ImGui::TextColored(theme::kRed, "Permanently destroys the target - cannot be undone.");
                ImGui::TextColored(theme::kTextDim, "File or folder path");
                ImGui::SetNextItemWidth(-1);
                ImGui::InputText("##shredpath", app.shredPath, sizeof(app.shredPath));
                ImGui::SetNextItemWidth(160);
                ImGui::SliderInt("passes", &app.shredPasses, 1, 5);
                ImGui::Checkbox("I understand this is irreversible", &app.shredConfirmed);
                bool busy = JobBusy(app);
                ImGui::BeginDisabled(busy || !app.shredConfirmed);
                ImGui::PushStyleColor(ImGuiCol_Button, theme::kRed);
                if (ImGui::Button("SHRED NOW", ImVec2(140, 0))) StartShred(app);
                ImGui::PopStyleColor();
                ImGui::EndDisabled();
                ImGui::Spacing();
                ImGui::ProgressBar(app.job.progress.load(), ImVec2(-1, 18));
            }
            EndCard();
        }

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

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
