# Secrets Manager

A self-hosted, single-binary secrets manager written in Rust — a lightweight
alternative to Infisical for a small VPS. Secrets are stored **encrypted at
rest** on the server and fetched by a client CLI that injects them directly
into a process's environment, so plaintext never touches disk.

> Design stance: **safety is prioritized over performance/memory.** Where a
> choice exists, the more conservative (slower/heavier) option is taken.

## Status

| Milestone | Scope | State |
|---|---|---|
| **M1** | Server: CRUD + encryption + token auth + admin CLI + tests | ✅ Done |
| **M2** | Client: `run` / `get` / `set` / `list` / `export` | ✅ Done |
| M3 | Offline encrypted cache, `rekey` (re-encrypt all), audit polish | ⏳ Planned |
| M4 | musl static build, systemd unit, nginx sample, GitHub Actions release | ⏳ Planned |

23 tests currently pass (11 crypto unit + 9 server integration + 3 client).

## Architecture

```
[secrets CLI] --HTTPS--> [nginx (TLS term)] --localhost--> [secrets-server]
                                                                 |
                                                          [SQLite: ciphertext only]
```

The server binds **loopback only**; TLS is terminated by a reverse proxy
(e.g. nginx) in front of it.

### Workspace layout

```
crates/
├─ secrets-crypto/   # pure crypto core, no I/O (fully unit-tested)
├─ secrets-server/   # axum + rusqlite; server + admin CLI (lib + bin)
└─ secrets-client/   # ureq-based client CLI `secrets` (lib + bin)
```

## Cryptography

- **AEAD:** XChaCha20-Poly1305. A fresh 24-byte nonce is generated from the
  OS CSPRNG (`OsRng`) on **every** write — never reused, fixed, or counter-based.
- **AAD:** each ciphertext is bound to its record via a length-prefixed
  encoding of `(project, key)`, so a ciphertext cannot be swapped between
  records (tamper is detected on decrypt).
- **KDF:** Argon2id, hardened to **m = 256 MiB, t = 4, p = 1** (above the
  spec's 64 MiB baseline). The salt and parameters are stored in the DB.
- **Master key** lives only in memory (`Zeroizing`, wiped on drop) and is
  never printed (`Debug` is redacted).
- **Passphrase verification:** on startup the server decrypts an encrypted
  sentinel stored in a `meta` table. A wrong passphrase fails loudly **before
  the socket is bound** — it never serves with a bad key.
- **Tokens:** only a `SHA-256` hash is stored (never the token). Comparison is
  constant-time (`subtle`). All crypto uses RustCrypto crates — no custom
  crypto, no custom protocols.

## Build

Requires a stable Rust toolchain (see `rust-toolchain.toml`).

```bash
cargo build --release            # both binaries
cargo test --workspace           # all tests
cargo clippy --workspace --all-targets
```

Binaries: `target/release/secrets-server` and `target/release/secrets`.

## Server usage

The server takes its master passphrase from `SECRETS_PASSPHRASE` (intended to
be supplied by systemd `LoadCredential`) or, if absent and attached to a TTY,
an interactive prompt.

Environment variables:

| Var | Default | Meaning |
|---|---|---|
| `SECRETS_PASSPHRASE` | — | master passphrase (else TTY prompt) |
| `SECRETS_DB_PATH` | `secrets.db` | SQLite path |
| `SECRETS_AUDIT_PATH` | `audit.jsonl` | audit log path |
| `SECRETS_BIND` | `127.0.0.1:8787` | listen address (keep loopback) |

```bash
# Issue a token (printed once, never stored in plaintext).
SECRETS_PASSPHRASE=... secrets-server token create --name macbook --project cdn
secrets-server token list
secrets-server token revoke --name macbook

# Run the server.
SECRETS_PASSPHRASE=... secrets-server serve
```

### HTTP API (all except `/v1/health` require `Authorization: Bearer <token>`)

| Method | Path | Description |
|---|---|---|
| GET | `/v1/health` | `{"status":"ok"}` — no auth |
| GET | `/v1/projects` | list projects (scoped tokens see only their own) |
| POST | `/v1/projects` | create project — body `{"name":"cdn"}` |
| GET | `/v1/projects/{name}/secrets` | decrypted `{key: value}` map |
| PUT | `/v1/projects/{name}/secrets/{key}` | set — body `{"value":"..."}` |
| DELETE | `/v1/projects/{name}/secrets/{key}` | delete |

A token scoped to a project returns **403** for any other project; revoked or
invalid tokens return **401**.

### Audit log

Append-only JSON Lines (`audit.jsonl`), one record per request:
`{ts, token, method, path, status}`. The token **name** is recorded — never
the token value, never any secret value.

## Client usage (`secrets`)

Config file `~/.config/secrets/config.toml` (override with `SECRETS_CONFIG`):

```toml
server_url = "https://secrets.example.com"
token = "..."
```

`SECRETS_TOKEN` and `SECRETS_SERVER_URL` environment variables take precedence
(handy in CI). On Unix, the client warns if the config file is more permissive
than `600`.

```bash
# Inject secrets into a process (nothing written to disk).
secrets run --project cdn -- go run ./cmd/server

secrets set  --project cdn DATABASE_URL     # value read from stdin/hidden prompt
secrets get  --project cdn DATABASE_URL     # single value to stdout
secrets list --project cdn                  # key names only
secrets export --project cdn --format dotenv   # dotenv to stdout (explicit opt-in)
```

- `set` never takes the value on the command line (it would leak via `ps` /
  shell history) — it reads from stdin or a hidden prompt.
- `run` injects secrets into the **child** environment only (Unix `execvp`,
  Windows spawn+wait), propagates the child exit code, and never pollutes the
  parent environment or writes a `.env` file.

> Projects are provisioned via `POST /v1/projects` (admin/API); the client has
> no project-create command.

## Security notes / non-goals

- Serve over plain HTTP on loopback **only**, behind a TLS-terminating proxy.
- No secret value, token, key, or passphrase is ever written to logs, error
  messages, or debug output.
- Offline caching, key rotation (`rekey`), and packaging (systemd/nginx/CI) are
  planned for M3–M4 and not yet implemented.

## License

MIT.
