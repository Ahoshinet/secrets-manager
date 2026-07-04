# Secrets Manager HTTP API (`/v1`)

This document is the **source of truth** for the wire contract between the
server and every client (the Rust `secrets-client` crate, the Go
[`secrets-manager-go`](https://github.com/Ahoshinet/secrets-manager-go) module,
and any future client). Change this document and the server together; clients
track it.

## Transport & auth

- The server binds **loopback only** and speaks plain HTTP; TLS is terminated by
  a reverse proxy in front of it. Clients therefore require an `https://` server
  URL (they refuse plain `http://`).
- Every endpoint **except `GET /v1/health`** requires a bearer token:
  `Authorization: Bearer <token>`.
- A token may be **scoped** to a single project. A scoped token accessing any
  other project receives `403`. `GET /v1/projects` returns only the scoped
  project for such tokens.
- Request and response bodies are JSON (`Content-Type: application/json`).
  Bodies are size-limited by the server; clients cap response reads at 1 MiB.

## Validation rules

| Field | Rule |
|---|---|
| project name | non-empty, ≤ 64 bytes, `[A-Za-z0-9_-]` only |
| secret key | non-empty, ≤ 128 bytes, `[A-Za-z0-9_.-]` only |

Violations return `400`.

## Status codes

| Code | Meaning |
|---|---|
| 200 | OK (body follows) |
| 201 | Created (project) |
| 204 | No Content (delete) |
| 400 | Bad Request (invalid project/key name or body) |
| 401 | Unauthorized (missing/invalid/revoked token) |
| 403 | Forbidden (token not scoped to this project) |
| 404 | Not Found (unknown project or key) |
| 409 | Conflict (project already exists) |

No error response ever includes secret material, token values, or the master
passphrase.

## Endpoints

### `GET /v1/health` — liveness (no auth)

```json
200 OK
{ "status": "ok" }
```

### `GET /v1/projects` — list projects

Scoped tokens see only their own project.

```json
200 OK
{ "projects": [ { "name": "cdn", "created_at": "2026-07-04T12:00:00Z" } ] }
```

### `POST /v1/projects` — create a project

```json
// request
{ "name": "cdn" }

201 Created
{ "name": "cdn" }
```

Returns `400` for an invalid name, `409` if the project already exists.
(Provisioning is an admin/API operation; the CLI clients do not expose it.)

### `GET /v1/projects/{project}/secrets` — fetch all secrets

Returns a flat map of **decrypted** key → value for the project.

```json
200 OK
{ "DATABASE_URL": "postgres://…", "API_KEY": "…" }
```

`404` if the project does not exist.

### `PUT /v1/projects/{project}/secrets/{key}` — set one secret

The value is created or updated (upsert); `version` is the new monotonic
version of that key.

```json
// request
{ "value": "postgres://…" }

200 OK
{ "key": "DATABASE_URL", "version": 2 }
```

`400` for an invalid key, `404` if the project does not exist.

### `DELETE /v1/projects/{project}/secrets/{key}` — delete one secret

```
204 No Content
```

`404` if the project or key does not exist.

## Notes for client authors

- Send the token **only** in the `Authorization` header — never in the URL,
  query string, or logs.
- Treat secret values as sensitive in memory: prefer a wrapping/zeroizable type
  over plain strings, and never print them (including in `Debug`/`String`).
- Only transport-level failures should trigger any offline-cache fallback;
  auth/HTTP status failures (401/403/404) must **not** fall back to cache.
