# Security policy

SecureVault encrypts files, so security problems matter here. Thank you for reporting them responsibly.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately instead:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability** and describe what you found.

Please include:
- what you found and why it matters
- the SecureVault version (shown in the window title, or run `securevault-cli version`)
- steps to reproduce, or a sample file if that helps
- your operating system

The maintainer will try to reply within about a week. This is a hobby project, so there is no guaranteed response time, but every report will be read.

## What counts

Examples of things worth reporting:
- a way to decrypt, or to forge or modify, a file without the password or key file
- a flaw in the file format or in how keys or nonces are made
- a path traversal or similar bug when extracting an encrypted folder
- a crash or memory-safety bug triggered by a crafted file
- a password or key leaking into a log, a file, or the clipboard when it should not

Not security bugs: weak passwords, losing a key file, plaintext copies you made yourself, or the limits already listed in [THREAT_MODEL.md](THREAT_MODEL.md) (for example, secure shredding on SSDs).

## Supported versions

Only the latest release gets fixes. Older files stay readable by newer versions.

## No audit

SecureVault has not had an independent security review. See [THREAT_MODEL.md](THREAT_MODEL.md) for what it does and does not protect against.
