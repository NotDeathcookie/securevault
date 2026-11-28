// theme.hpp - "Rose Vault" visual theme: dark magenta/plum background,
// neon-pink accents, soft rounded cards - styled after the reference
// dashboard screenshot (deep maroon panels, pink glow, pill buttons).
#pragma once
#include "imgui.h"
#include <cmath>

namespace theme {

// Palette. Default is the pink-neon theme; building with SV_THEME_MAROON selects
// a near-black / dark maroon / blood-red variant.
#if defined(SV_THEME_MAROON)
inline const ImVec4 kBgTop         = ImVec4(0.04f, 0.015f, 0.015f, 1.00f);
inline const ImVec4 kBgBottom      = ImVec4(0.14f, 0.035f, 0.035f, 1.00f);
inline const ImVec4 kCard          = ImVec4(0.13f, 0.045f, 0.045f, 0.92f);
inline const ImVec4 kCardHover     = ImVec4(0.18f, 0.060f, 0.060f, 0.95f);
inline const ImVec4 kCardBorder    = ImVec4(0.75f, 0.140f, 0.120f, 0.35f);
inline const ImVec4 kPink          = ImVec4(0.80f, 0.130f, 0.110f, 1.00f);  // accent
inline const ImVec4 kPinkSoft      = ImVec4(0.80f, 0.130f, 0.110f, 0.55f);
inline const ImVec4 kPinkDim       = ImVec4(0.42f, 0.090f, 0.080f, 1.00f);
inline const ImVec4 kGold          = ImVec4(0.92f, 0.600f, 0.220f, 1.00f);
inline const ImVec4 kGreen         = ImVec4(0.45f, 0.850f, 0.500f, 1.00f);
inline const ImVec4 kRed           = ImVec4(0.95f, 0.300f, 0.280f, 1.00f);
inline const ImVec4 kTextDim       = ImVec4(0.78f, 0.660f, 0.660f, 0.70f);
inline const ImVec4 kTextBright    = ImVec4(0.97f, 0.930f, 0.930f, 1.00f);
inline const ImVec4 kFrame         = ImVec4(0.08f, 0.030f, 0.030f, 0.85f);
inline const ImVec4 kFrameHover    = ImVec4(0.20f, 0.070f, 0.060f, 0.90f);
inline const ImVec4 kFrameActive   = ImVec4(0.26f, 0.090f, 0.080f, 0.95f);
inline const ImVec4 kButtonBase    = ImVec4(0.26f, 0.080f, 0.070f, 1.00f);
inline const ImVec4 kTabBase       = ImVec4(0.18f, 0.060f, 0.060f, 1.00f);
inline const ImVec4 kScrollBg      = ImVec4(0.08f, 0.030f, 0.030f, 0.60f);
inline const ImVec4 kPopup         = ImVec4(0.10f, 0.035f, 0.035f, 0.98f);
#else
inline const ImVec4 kBgTop         = ImVec4(0.09f, 0.03f, 0.08f, 1.00f);  // near-black plum
inline const ImVec4 kBgBottom      = ImVec4(0.16f, 0.05f, 0.13f, 1.00f);  // deep maroon
inline const ImVec4 kCard          = ImVec4(0.17f, 0.06f, 0.15f, 0.92f);
inline const ImVec4 kCardHover     = ImVec4(0.21f, 0.08f, 0.19f, 0.95f);
inline const ImVec4 kCardBorder    = ImVec4(0.85f, 0.25f, 0.55f, 0.35f);
inline const ImVec4 kPink          = ImVec4(0.98f, 0.25f, 0.58f, 1.00f);  // primary neon pink
inline const ImVec4 kPinkSoft      = ImVec4(0.98f, 0.25f, 0.58f, 0.55f);
inline const ImVec4 kPinkDim       = ImVec4(0.55f, 0.18f, 0.38f, 1.00f);
inline const ImVec4 kGold          = ImVec4(0.98f, 0.80f, 0.35f, 1.00f);
inline const ImVec4 kGreen         = ImVec4(0.45f, 0.92f, 0.55f, 1.00f);
inline const ImVec4 kRed           = ImVec4(0.95f, 0.30f, 0.35f, 1.00f);
inline const ImVec4 kTextDim       = ImVec4(0.80f, 0.68f, 0.76f, 0.70f);
inline const ImVec4 kTextBright    = ImVec4(0.98f, 0.94f, 0.97f, 1.00f);
inline const ImVec4 kFrame         = ImVec4(0.10f, 0.04f, 0.09f, 0.85f);
inline const ImVec4 kFrameHover    = ImVec4(0.22f, 0.08f, 0.18f, 0.90f);
inline const ImVec4 kFrameActive   = ImVec4(0.28f, 0.10f, 0.22f, 0.95f);
inline const ImVec4 kButtonBase    = ImVec4(0.30f, 0.10f, 0.22f, 1.00f);
inline const ImVec4 kTabBase       = ImVec4(0.20f, 0.07f, 0.17f, 1.00f);
inline const ImVec4 kScrollBg      = ImVec4(0.10f, 0.04f, 0.09f, 0.60f);
inline const ImVec4 kPopup         = ImVec4(0.12f, 0.04f, 0.10f, 0.98f);
#endif

inline void Apply(ImGuiStyle& style) {
    style.WindowRounding    = 14.0f;
    style.ChildRounding     = 16.0f;
    style.FrameRounding     = 10.0f;
    style.PopupRounding     = 10.0f;
    style.ScrollbarRounding = 12.0f;
    style.GrabRounding      = 10.0f;
    style.TabRounding       = 10.0f;
    style.WindowBorderSize  = 0.0f;
    style.ChildBorderSize   = 1.5f;
    style.FrameBorderSize   = 1.0f;
    style.WindowPadding     = ImVec2(18, 16);
    style.FramePadding      = ImVec2(12, 8);
    style.ItemSpacing       = ImVec2(10, 10);
    style.IndentSpacing     = 18.0f;

    ImVec4* c = style.Colors;
    c[ImGuiCol_WindowBg]          = kBgBottom;
    c[ImGuiCol_ChildBg]           = kCard;
    c[ImGuiCol_Border]            = kCardBorder;
    c[ImGuiCol_FrameBg]           = kFrame;
    c[ImGuiCol_FrameBgHovered]    = kFrameHover;
    c[ImGuiCol_FrameBgActive]     = kFrameActive;
    c[ImGuiCol_Text]              = kTextBright;
    c[ImGuiCol_TextDisabled]      = kTextDim;
    c[ImGuiCol_Button]            = kButtonBase;
    c[ImGuiCol_ButtonHovered]     = ImVec4(kPink.x, kPink.y, kPink.z, 0.85f);
    c[ImGuiCol_ButtonActive]      = kPink;
    c[ImGuiCol_Header]            = ImVec4(kPink.x, kPink.y, kPink.z, 0.35f);
    c[ImGuiCol_HeaderHovered]     = ImVec4(kPink.x, kPink.y, kPink.z, 0.55f);
    c[ImGuiCol_HeaderActive]      = ImVec4(kPink.x, kPink.y, kPink.z, 0.75f);
    c[ImGuiCol_CheckMark]         = kPink;
    c[ImGuiCol_SliderGrab]        = kPink;
    c[ImGuiCol_SliderGrabActive]  = kGold;
    c[ImGuiCol_Tab]               = kTabBase;
    c[ImGuiCol_TabHovered]        = ImVec4(kPink.x, kPink.y, kPink.z, 0.7f);
    c[ImGuiCol_TabActive]         = kPinkDim;
    c[ImGuiCol_PlotLines]         = kPink;
    c[ImGuiCol_PlotLinesHovered]  = kGold;
    c[ImGuiCol_PlotHistogram]     = kPink;
    c[ImGuiCol_ScrollbarBg]       = kScrollBg;
    c[ImGuiCol_ScrollbarGrab]     = kPinkDim;
    c[ImGuiCol_ScrollbarGrabHovered] = kPink;
    c[ImGuiCol_Separator]         = kCardBorder;
    c[ImGuiCol_PopupBg]           = kPopup;
}

// Draws the diagonal plum->maroon backdrop gradient plus a few soft
// "petal" glow blobs, reminiscent of the reference screenshot's floral
// background motif. Call first thing, before any windows.
inline void DrawBackdrop(ImDrawList* dl, ImVec2 size) {
    dl->AddRectFilledMultiColor(
        ImVec2(0, 0), size,
        ImGui::ColorConvertFloat4ToU32(kBgTop), ImGui::ColorConvertFloat4ToU32(kBgTop),
        ImGui::ColorConvertFloat4ToU32(kBgBottom), ImGui::ColorConvertFloat4ToU32(kBgBottom));

    auto glow = [&](ImVec2 center, float radius, ImU32 col) {
        dl->AddCircleFilled(center, radius, col, 48);
    };
    ImU32 soft = ImGui::ColorConvertFloat4ToU32(ImVec4(kPink.x, kPink.y, kPink.z, 0.05f));
    glow(ImVec2(size.x * 0.12f, size.y * 0.18f), 160.0f, soft);
    glow(ImVec2(size.x * 0.85f, size.y * 0.30f), 220.0f, soft);
    glow(ImVec2(size.x * 0.65f, size.y * 0.85f), 200.0f, soft);
    glow(ImVec2(size.x * 0.25f, size.y * 0.80f), 150.0f, soft);
}

// A small 6-petal flower glyph drawn with primitives, used as the logo mark
// and as a decorative watermark on card headers (echoes the floral motif).
inline void DrawFlower(ImDrawList* dl, ImVec2 center, float r, ImU32 petalCol, ImU32 centerCol) {
    for (int i = 0; i < 6; i++) {
        float a = (float)i / 6.0f * 2.0f * 3.14159265f;
        ImVec2 p = ImVec2(center.x + cosf(a) * r * 0.6f, center.y + sinf(a) * r * 0.6f);
        dl->AddCircleFilled(p, r * 0.55f, petalCol, 20);
    }
    dl->AddCircleFilled(center, r * 0.45f, centerCol, 20);
}

}  // namespace theme
