# Secure Vault (C++ GUI edition)

A C++17 / Dear ImGui rewrite of `secure_vault-wy-hash.py`. Same crypto
(AES-256-GCM, PBKDF2-HMAC-SHA256 @ 600,000 rounds), same file container
format for `.enc` files, same multi-pass shredding and multi-algorithm
hashing — now with a GUI styled after the pink-neon card dashboard you
provided, instead of a terminal menu.

Prebuilt binaries are attached to each GitHub Release, and every push builds Windows and Linux artifacts via GitHub Actions.

## Layout

```
src/
  vault.hpp / vault.cpp   crypto + file/folder/hash/shred logic (OpenSSL)
  theme.hpp               colors, rounded "card" styling, flower glyph, backdrop
  main.cpp                Dear ImGui dashboard UI + app state
third_party/imgui/        Dear ImGui (vendored, trimmed to what's needed)
CMakeLists.txt
```

## What maps to what, vs. the screenshot

| Screenshot card      | This app                                             |
|-----------------------|-------------------------------------------------------|
| Top bar / logo / tabs | VAULT logo, Home / Log / Tools tabs, PRIVATE toggle   |
| STAGE / mode buttons  | OPERATION card: TEXT / FILE / FOLDER + ENCRYPT/DECRYPT pills |
| PREDICTION / CAPTURE  | STATUS card: idle/running dot, cipher + KDF info      |
| AUTOPLAY / Start      | Password or key-file input + START button + progress bar |
| WEAKEST %             | RESULT card: decrypted text / payload / messages      |
| ONLINE NOW graph      | ACTIVITY card: live progress sparkline + op counter   |
| ALL LEVELS stats      | STATISTICS card: attempts / successes / failures / rate |
| Footer toggles        | PRIVATE mode masks the password field and hides the log |

`Tools` holds standalone **Hash a file** and **Secure shred** (these don't
need a password, so they're split out from the main encrypt/decrypt flow).

## Building from source

Dependencies (Ubuntu/Debian):
```
apt-get install build-essential cmake pkg-config libglfw3-dev libssl-dev libgl1-mesa-dev
```

```
mkdir build && cd build
cmake ..
make -j4
./securevault
```

On macOS: `brew install glfw openssl cmake`, then point CMake at OpenSSL
with `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl)`.

### Windows

A prebuilt, statically-linked `securevault.exe` is available from Releases — it
only touches standard Windows DLLs (bcrypt, gdi32, opengl32, user32, etc.),
so it runs on a bare Windows machine with nothing extra installed, and you
can copy just that one file anywhere.

To build it yourself (e.g. via MSYS2 UCRT64 — `pacman -S --needed
base-devel mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake
mingw-w64-ucrt-x86_64-glfw`):

```
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
cmake --build .
```

On Windows this build uses the OS's own crypto (CNG/`bcrypt.h`), **not
OpenSSL** — so there's no OpenSSL dependency to install on Windows at all;
`find_package(OpenSSL)` only runs on Linux/macOS. If you want the resulting
`.exe` to run on machines that don't have MSYS2 installed, statically link
the compiler runtime, or it'll depend on `libstdc++-6.dll` /
`libgcc_s_seh-1.dll` / `libwinpthread-1.dll` / `glfw3.dll` from your MSYS2
install:

```
cmake --build . -- LDFLAGS="-static-libgcc -static-libstdc++ -static -mwindows"
```

(or add `target_link_options(securevault PRIVATE -static-libgcc
-static-libstdc++ -static -mwindows)` to `CMakeLists.txt`, which is already
done for you — it only applies when CMake's target platform is Windows.)

## Notes on the port

- **Folder encryption** no longer depends on Python's `zipfile`. It uses a
  small custom container (relative path + size + bytes per file, recursively)
  before running it through the same chunked AES-GCM file encryption — so no
  extra zip library dependency. It is *not* ZIP-compatible, but round-trips
  losslessly (verified in testing).
- **File `.enc` format** is byte-for-byte compatible with the Python
  version's layout: `salt(16)` header, then repeated
  `[u32 big-endian length][nonce(12) || ciphertext || tag(16)]` chunks — so
  files encrypted by one implementation decrypt correctly in the other.
- Long operations (file/folder encrypt/decrypt, hashing, shredding) run on a
  background thread so the UI stays responsive and shows a live progress bar.
- This build was compiled and round-trip tested in a headless container
  (no display attached), so the window itself could not be visually
  screenshotted here — but the link/compile succeeded and the crypto/file/
  hash/shred logic in `vault.cpp` was exercised end-to-end via a standalone
  test (text encrypt/decrypt incl. wrong-password rejection, file round-trip,
  folder round-trip via `diff -r`, hashing, and shredding). Please run it on
  your machine to confirm the on-screen look — if anything about the layout
  should be adjusted to better match your reference image, let me know.

## License

MIT — see `LICENSE`. Bundled third-party code: Dear ImGui (MIT, `third_party/imgui/LICENSE.txt`). GLFW (zlib) and OpenSSL (Apache-2.0, Linux/macOS builds only) are linked, not bundled.

## Security note

This is a hobby project and has not been independently audited. Don't rely on it as your only copy of anything important.
