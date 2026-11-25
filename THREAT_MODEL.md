# SecureVault threat model

SecureVault encrypts text, files, and folders with a password or key file.
This document says what that protects against and what it doesn't.

## What it protects against

- **Someone who gets the encrypted file but not your password or key file.**
  Contents are encrypted with AES-256-GCM. The key is derived from your
  password with PBKDF2-HMAC-SHA256 (600,000 iterations) and a random 16-byte
  salt, so every file has a different key.
- **Tampering.** Every chunk is authenticated. Changing, reordering,
  duplicating, or removing chunks, cutting the file short, appending data, or
  editing the header makes decryption fail.
- **Guessing at scale.** The iteration count slows password guessing, but it
  can't save a weak password. Use a long passphrase or a key file.

## What it does not protect against

- **Malware or an attacker on your computer.** Anything that can read memory,
  log keystrokes, or watch files while you work can see your password and
  your plaintext.
- **Plaintext copies.** The original file stays where it was. Temporary
  files, backups, cloud sync, and swap/pagefile may hold copies.
- **Metadata.** File size (to within a chunk), file name, and timestamps of the
  encrypted file are visible. Folder encryption hides the names inside the
  archive, but not the archive's size.
- **Weak passwords.** Offline guessing is slowed, not prevented.
- **Secure deletion.** Shredding overwrites a file's contents once or a few
  times. On SSDs, journaling or copy-on-write filesystems, and synced folders,
  old copies of the data can survive. It is best effort, not a guarantee.
- **Password recovery.** There is none. Lose the password or key file and the
  data is gone.
- **Memory hygiene.** Keys and passwords are not locked in memory or reliably
  wiped after use.

## Not audited

No independent security review has been done. Treat it as a hobby project and
don't use it as the only copy of important data.

## File format (v2)

```
header (25 bytes):  "SVLT" | version=0x02 | chunk_size u32 BE | salt (16)
chunk, repeated:    u32 BE word | AES-256-GCM ciphertext + 16-byte tag
                    word = (final_flag << 31) | ciphertext_length
```

- Key = PBKDF2-HMAC-SHA256(password or key file bytes, salt, 600,000).
- Nonce = 4 zero bytes followed by the chunk index as a 64-bit big-endian
  counter. This is safe because each file has its own random salt, so its own
  key.
- Associated data for every chunk = the whole header plus one byte for the
  final flag.
- A valid file has exactly one final chunk, and it is the last chunk. Empty
  files are stored as a single empty final chunk.
- Folders are packed into a simple archive (relative path, size, bytes per
  file) and then encrypted as one file. Paths that are absolute or contain
  `..` are rejected on extraction.
- Text is stored as base64 of `salt (16) | nonce (12) | ciphertext | tag`,
  with a random nonce.
- Files from v1.0 (no header, no ordering protection) can still be decrypted.
  Re-encrypt them to get the v2 protections.
