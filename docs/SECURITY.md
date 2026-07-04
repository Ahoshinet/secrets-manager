# Security model and residual risks

This document records deliberate security decisions and the residual risks
that remain **by design**, so they are not re-litigated on every audit.

## What is protected

- Secrets at rest: XChaCha20-Poly1305 AEAD, key derived from the master
  passphrase via Argon2id (m=256 MiB, t=4, p=1), random per-secret nonces,
  AAD binding `(project, key)` so ciphertexts cannot be swapped between rows.
- KDF parameters read back from the database are bounds-checked before
  derivation (the meta table is not authenticated).
- Tokens: only SHA-256 hashes are stored; comparison is constant-time;
  tokens expire (90-day default) and can be revoked.
- Offline cache: AEAD-encrypted with a per-user key (DPAPI on Windows,
  Keychain on macOS, 0600 key file elsewhere); the AAD binds server URL,
  token hash, project, **and creation timestamp**, so a cache-file writer
  cannot extend the 24 h TTL or replay stale ciphertext.
- Process exclusivity: the server holds an exclusive lock on the database
  for its lifetime; `rekey` requires that lock, so a live server can never
  keep encrypting under a superseded master key.
- Files: passphrase file, audit log, cache files and cache key are opened
  with `O_NOFOLLOW` on Unix and validated via the opened fd (regular file,
  owner-only permissions) — the checks cannot be raced against the open.
- Audit log: records token *name*, method, matched route template, project
  name, and status. Raw request paths (which may embed secret key names or
  attacker-chosen segments) are never written.

## Residual risks (accepted)

### Plaintext copies in process memory

Secret values and bearer tokens are wrapped in `secrecy`/`Zeroizing` types
and wiped where we control the buffer (request/response bodies we assemble,
dotenv output, auth headers, cache plaintext). However:

- serializers (`serde_json`), the HTTP stack (axum/hyper, ureq), and OS
  socket buffers make internal copies we cannot reach;
- `secrets run` hands values to the child process environment, whose
  lifetime we do not control;
- a debugger or memory dump taken *while a request is in flight* can
  observe plaintext.

Full elimination would require a zeroizing allocator across every
dependency. The accepted posture: protect against *at-rest* disclosure and
post-hoc buffer reuse, not against an attacker who can already read live
process memory (such an attacker can also read the master key).

### Same-host plaintext loopback

Clients accept `http://` for loopback addresses only. Loopback traffic
never crosses a network interface; an attacker who can sniff loopback owns
the host anyway. All non-loopback traffic must be `https://`.

### Windows file permissions

Unix builds enforce 0600/0700 modes. On Windows, per-user protection comes
from DPAPI (cache key) and default user-profile ACLs; explicit ACL
tightening is not implemented.
