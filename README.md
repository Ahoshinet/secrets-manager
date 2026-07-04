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
| **M3** | Offline encrypted cache, `rekey` (re-encrypt all), audit polish | ✅ Done |
| **M4** | musl static build, systemd unit, nginx sample, GitHub Actions release | ✅ Done |
| **M5** | Rust client library polish: typed errors, CLI feature gate, secret-safe values | ✅ Done |
| **M6** | Native Go client library | ✅ Done |

Rust: 28 tests currently pass (11 crypto unit + 10 server integration + 7 client/server unit).
Go client: 5 tests currently pass.

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
clients/
└─ go/                # native Go client library
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

### Static Linux build

For a self-contained Linux release build:

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install musl-tools
cargo build --release --locked --target x86_64-unknown-linux-musl --bins
```

The tag release workflow builds this target and verifies the produced binaries
do not declare dynamic dependencies.

## Server usage

The server takes its master passphrase from (in this order)
`SECRETS_PASSPHRASE`, `SECRETS_PASSPHRASE_FILE`, systemd
`LoadCredential=secrets-passphrase`, or, if attached to a TTY, an interactive
prompt. **Prefer a passphrase file, the systemd credential, or the interactive
prompt** — an inline `SECRETS_PASSPHRASE=...` on the command line lands in
shell history and is visible in the process environment. Passphrase files must
be private on Unix (no group/other permissions) and must not be symlinks; a
single trailing newline is ignored.

Environment variables:

| Var | Default | Meaning |
|---|---|---|
| `SECRETS_PASSPHRASE` | — | master passphrase |
| `SECRETS_PASSPHRASE_FILE` | — | path to a private master passphrase file |
| `SECRETS_DB_PATH` | `secrets.db` | SQLite path |
| `SECRETS_AUDIT_PATH` | `audit.jsonl` | audit log path |
| `SECRETS_BIND` | `127.0.0.1:8787` | listen address (keep loopback) |

```bash
# Point the server at a private passphrase file (0600, not a symlink).
export SECRETS_PASSPHRASE_FILE=/etc/secrets-manager/master-passphrase

# Issue a token (printed once, never stored in plaintext).
# Tokens expire after 90 days by default; use --ttl-days N to adjust or
# --no-expiry for a token you will revoke manually.
secrets-server token create --name macbook --project cdn
secrets-server token list
secrets-server token revoke --name macbook

# Rekey requires exclusive access: stop the server first.
secrets-server rekey

# Run the server (holds an exclusive lock on the DB while running).
secrets-server serve
```

## Deployment

Sample deployment files live under `deploy/`:

- `deploy/systemd/secrets-server.service` runs `secrets-server serve` as a
  dedicated `secrets` user, keeps the HTTP bind on `127.0.0.1:8787`, stores the
  DB under `/var/lib/secrets-manager`, writes audit JSONL under
  `/var/log/secrets-manager`, and loads the master passphrase from
  `/etc/secrets-manager/master-passphrase` using systemd credentials.
- `deploy/nginx/secrets-manager.conf` terminates TLS and reverse-proxies to the
  loopback server. Replace `secrets.example.com` and certificate paths before
  enabling it.

Minimal Linux install sketch:

```bash
sudo install -m 0755 target/x86_64-unknown-linux-musl/release/secrets-server /usr/local/bin/secrets-server
sudo install -m 0755 target/x86_64-unknown-linux-musl/release/secrets /usr/local/bin/secrets
sudo useradd --system --home /var/lib/secrets-manager --shell /usr/sbin/nologin secrets
sudo install -d -m 0700 -o root -g root /etc/secrets-manager
sudo install -m 0600 -o root -g root /path/to/master-passphrase /etc/secrets-manager/master-passphrase
sudo install -m 0644 deploy/systemd/secrets-server.service /etc/systemd/system/secrets-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now secrets-server
```

Releases are created by GitHub Actions when a `v*` tag is pushed. The release
archive contains static Linux binaries plus the deploy samples.

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
- Successful fetches are cached locally as encrypted ciphertext for 24 hours.
  The cache key is protected with macOS Keychain, Windows DPAPI, or a Linux/Unix
  `0600` key file under the cache directory. `--no-cache` on `run` / `get` /
  `list` / `export` disables cache reads and writes for that invocation.
- If the server is unreachable, `run` / `get` / `list` / `export` fall back to a
  fresh encrypted cache entry and print a warning to stderr. Auth failures and
  HTTP errors do not use the cache.

> Projects are provisioned via `POST /v1/projects` (admin/API); the client has
> no project-create command.

### Rust library usage

`secrets-client` can be embedded directly by Rust applications. The public API
uses a typed `secrets_client::Error` and returns values as `SecretString` rather
than plaintext `String`.

```rust
use secrets_client::{Api, Config};

let cfg = Config {
    server_url: "https://secrets.example.com".to_string(),
    token: secrecy::SecretString::from("token".to_string()),
};
let api = Api::new(&cfg);
let secrets = api.get_secrets("cdn")?;
let database_url = secrets.get("DATABASE_URL");
```

CLI-only dependencies (`clap`, `rpassword`, `anyhow`) are behind the `cli`
feature. It is enabled by default for normal binary builds; library consumers
can disable default features when they do not need the CLI.

### Go library usage

The native Go client lives in its own repository:
**[Ahoshinet/secrets-manager-go](https://github.com/Ahoshinet/secrets-manager-go)**.
It speaks the same HTTP API over HTTPS, tracking the contract in
[`docs/API.md`](docs/API.md).

```bash
go get github.com/Ahoshinet/secrets-manager-go@latest
```

```go
import secrets "github.com/Ahoshinet/secrets-manager-go"

client, err := secrets.New(secrets.Config{
    ServerURL: "https://secrets.example.com",
    Token:     token,
})
if err != nil {
    return err
}
values, err := client.GetSecrets(ctx, "cdn")
if err != nil {
    return err
}
databaseURL := values["DATABASE_URL"]
defer databaseURL.Zeroize()
```

## Security notes / non-goals

- Serve over plain HTTP on loopback **only**, behind a TLS-terminating proxy.
- No secret value, token, key, or passphrase is ever written to logs, error
  messages, or debug output.
- Use the included systemd/nginx samples as the production shape: plain HTTP on
  loopback, TLS at nginx, and the master passphrase supplied through a private
  file or systemd credential.

## License

BSD 2-Clause. See [LICENSE](LICENSE).
