# SecureVault

An open-source desktop app for encrypting text, files, and folders, with secure file shredding and file hashing built in. Written in C++ with a custom [Dear ImGui](https://github.com/ocornut/imgui) interface.

## Features

- **Encrypt and decrypt** text, single files, and whole folders
- **AES-256-GCM** authenticated encryption, so a wrong password or tampered data is detected rather than silently producing garbage
- **PBKDF2-HMAC-SHA256** key derivation (600,000 iterations) with a random salt per file
- **Password or key file**: unlock with a passphrase, or use any file as the key
- **Secure shred**: overwrite files or folders with random data (1 to 5 passes) before deleting
- **File hashing**: SHA-256, SHA-512, SHA-384, SHA-1, MD5
- **Private mode**: masks the password field and hides the activity log
- Large files are processed in 64 KB chunks on a background thread, with a live progress bar

## Download

Grab the latest build from the [Releases](../../releases) page.

- **Windows:** download `securevault.exe` and run it. No installer and nothing else to install.
- **Linux:** extract the archive, run `chmod +x securevault`, then run it. Requires GLFW and OpenSSL (`libglfw3`, `libssl3`).

## Using it

1. Pick **TEXT**, **FILE**, or **FOLDER**, then **ENCRYPT** or **DECRYPT**.
2. Enter the text or the path to the file or folder.
3. Enter a password, or tick *Use key file* and give the path to your key file.
4. Click **START**.

Output naming:

| Operation | Output |
|---|---|
| Encrypt file | `name.ext.enc` next to the original |
| Decrypt file | original name (`.enc` removed), or `name.decrypted` |
| Encrypt folder | `foldername_folder.enc` |
| Decrypt folder | `foldername_restored/` |
| Encrypt text | base64 text shown in the Result box |

The original is never deleted automatically. Use the **Tools** tab to shred it once you've confirmed the encrypted copy works.

## Building from source

Requirements: a C++17 compiler, CMake 3.16+, GLFW 3, and OpenGL. Linux and macOS also need OpenSSL. Windows does not, because it uses the operating system's built-in crypto (CNG).

**Linux (Debian/Ubuntu)**
```
sudo apt install build-essential cmake pkg-config libglfw3-dev libssl-dev libgl1-mesa-dev
mkdir build && cd build
cmake ..
make -j4
./securevault
```

**macOS**
```
brew install glfw openssl cmake
mkdir build && cd build
cmake .. -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)
make -j4
```

**Windows (MSYS2 UCRT64)**
```
pacman -S --needed mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-glfw
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
cmake --build .
```
The CMake file links the compiler runtime statically on Windows, so the resulting `securevault.exe` runs on machines without MSYS2.

## Project layout

```
src/
  main.cpp                  UI and application state
  theme.hpp                 colors and styling
  vault.hpp / vault.cpp     text, file, folder, hash, and shred logic
  vault_crypto.hpp          crypto interface
  vault_crypto_openssl.cpp  Linux/macOS backend (OpenSSL)
  vault_crypto_win.cpp      Windows backend (CNG / bcrypt)
third_party/imgui/          Dear ImGui
original_python_source.py   the original Python prototype, kept for reference
```

## Technical details

- **File format:** a 16-byte salt, followed by chunks of `[4-byte big-endian length][12-byte nonce | ciphertext | 16-byte tag]`. Each chunk gets a fresh random nonce.
- **Text format:** base64 of `salt (16) | nonce (12) | ciphertext | tag (16)`.
- **Folders** are packed into a simple custom archive (relative path, size, bytes for each file) and then encrypted like a single file. This is not a ZIP file.

## Limitations

This is a hobby project and has **not been independently audited**. Don't rely on it as the only copy of anything important.

- Chunks are authenticated individually, but the file format does not protect against chunks being removed from the end or reordered.
- Secure shredding overwrites the file's contents, but on SSDs, journaling or copy-on-write filesystems, and synced folders (OneDrive, Dropbox), old copies of the data may still exist elsewhere. It is not a guarantee of unrecoverable deletion.
- There is no password recovery. If you lose the password or key file, the data is gone.

## Contributing

Issues and pull requests are welcome.

## License

MIT. See [LICENSE](LICENSE). Dear ImGui is bundled under its own MIT license (`third_party/imgui/LICENSE.txt`).
