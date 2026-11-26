// filedialog.hpp - opens the operating system's own file/folder picker.
// Windows: the standard Explorer dialog (IFileOpenDialog), in a separate window.
// Linux: uses `zenity` if it is installed; otherwise Browse() just returns false.
#pragma once
#include <string>

struct GLFWwindow;

namespace filedialog {

enum class Kind { OpenFile, PickFolder, SaveFile };

// Makes the dialog appear on top of (and modal to) this window.
void SetOwner(GLFWwindow* window);

// Blocks until the user picks something or cancels. On success returns true
// and stores the chosen path (UTF-8) in `out`.
bool Browse(Kind kind, std::string& out);

}  // namespace filedialog
