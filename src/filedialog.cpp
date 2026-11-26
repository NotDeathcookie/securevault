#include "filedialog.hpp"

#if defined(_WIN32)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shobjidl.h>

#include <GLFW/glfw3.h>
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>

namespace filedialog {

static HWND g_owner = nullptr;

void SetOwner(GLFWwindow* window) {
    g_owner = window ? glfwGetWin32Window(window) : nullptr;
}

static std::string ToUtf8(const wchar_t* w) {
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "";
    std::string s((size_t)len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
    return s;
}

static bool SaveDialog(std::string& out) {
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    bool needUninit = SUCCEEDED(hrInit);
    bool picked = false;

    IFileSaveDialog* dlg = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_IFileSaveDialog, reinterpret_cast<void**>(&dlg)))) {
        DWORD opts = 0;
        dlg->GetOptions(&opts);
        dlg->SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_OVERWRITEPROMPT);
        dlg->SetTitle(L"Save the new key file");
        dlg->SetFileName(L"securevault.key");
        dlg->SetDefaultExtension(L"key");
        COMDLG_FILTERSPEC filters[] = {
            {L"Key files (*.key)", L"*.key"},
            {L"All files", L"*.*"},
        };
        dlg->SetFileTypes(2, filters);
        dlg->SetFileTypeIndex(1);

        if (SUCCEEDED(dlg->Show(g_owner))) {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dlg->GetResult(&item))) {
                PWSTR path = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                    out = ToUtf8(path);
                    picked = !out.empty();
                    CoTaskMemFree(path);
                }
                item->Release();
            }
        }
        dlg->Release();
    }
    if (needUninit) CoUninitialize();
    return picked;
}

bool Browse(Kind kind, std::string& out) {
    if (kind == Kind::SaveFile) return SaveDialog(out);
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    bool needUninit = SUCCEEDED(hrInit);  // S_OK and S_FALSE both need a matching call
    bool picked = false;

    IFileOpenDialog* dlg = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_IFileOpenDialog, reinterpret_cast<void**>(&dlg)))) {
        DWORD opts = 0;
        dlg->GetOptions(&opts);
        opts |= FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST;
        opts |= (kind == Kind::PickFolder) ? FOS_PICKFOLDERS : FOS_FILEMUSTEXIST;
        dlg->SetOptions(opts);
        dlg->SetTitle(kind == Kind::PickFolder ? L"Select a folder" : L"Select a file");

        if (kind == Kind::OpenFile) {
            COMDLG_FILTERSPEC filters[] = {
                {L"All files", L"*.*"},
                {L"SecureVault files (*.enc)", L"*.enc"},
            };
            dlg->SetFileTypes(2, filters);
            dlg->SetFileTypeIndex(1);
        }

        if (SUCCEEDED(dlg->Show(g_owner))) {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dlg->GetResult(&item))) {
                PWSTR path = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                    out = ToUtf8(path);
                    picked = !out.empty();
                    CoTaskMemFree(path);
                }
                item->Release();
            }
        }
        dlg->Release();
    }

    if (needUninit) CoUninitialize();
    return picked;
}

}  // namespace filedialog

#else  // Linux / macOS: best effort via zenity

#include <cstdio>

namespace filedialog {

void SetOwner(GLFWwindow*) {}

bool Browse(Kind kind, std::string& out) {
    const char* cmd =
        kind == Kind::PickFolder ? "zenity --file-selection --directory 2>/dev/null"
        : kind == Kind::SaveFile ? "zenity --file-selection --save --confirm-overwrite "
                                   "--filename=securevault.key 2>/dev/null"
                                 : "zenity --file-selection 2>/dev/null";
    FILE* p = popen(cmd, "r");
    if (!p) return false;
    char buf[4096];
    std::string result;
    if (fgets(buf, sizeof(buf), p)) result = buf;
    int rc = pclose(p);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) result.pop_back();
    if (rc != 0 || result.empty()) return false;
    out = result;
    return true;
}

}  // namespace filedialog

#endif
