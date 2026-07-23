# quicgate API

The management API is served on the admin port (`QG_ADMIN`, default `:81`) — the same origin as the web UI. All routes return JSON unless noted.

## Authentication

Two schemes; either works on every `/api/*` route except the public ones (`/api/login`, `/api/oidc/*`, `/api/auth-methods`).

**Session cookie** — `POST /api/login`, then send the `qg_session` cookie. Used by the web UI.

**API token (Bearer)** — for automation. Create one in the UI (Profile → API tokens) or via `POST /api/tokens`, then:

```bash
curl -H "Authorization: Bearer qg_xxxxxxxx" https://quicgate.example.com/api/hosts
```

Tokens are shown once at creation and stored only as a SHA-256 hash. Bearer auth bypasses the session and 2FA, so treat tokens as full-access credentials.

The admin port itself should stay network-gated (e.g. behind Pangolin/an IP allow-list); the API has no per-token scoping.

## Conventions

- Request/response bodies are JSON. Mutating host/access-list/stream/settings endpoints reject unknown fields (the "no silent drop" contract) — a typo'd key returns `400`.
- Errors: non-2xx with `{"error": "message"}`.
- IDs are integers in the path (`/api/hosts/{id}`).
- Every create/update/delete triggers an atomic engine reload; no restart.

## Auth & account

| Method | Path | Body / notes |
|---|---|---|
| POST | `/api/login` | `{email, password, code?}`. Returns `{email, mustChange, totpEnabled}`. If 2FA is on and `code` is omitted, returns `{totpRequired:true}` — resend with `code`. |
| POST | `/api/logout` | Clears the session. |
| GET | `/api/me` | Current user: `{email, mustChange, totpEnabled}`. |
| POST | `/api/password` | `{current, new}` (new ≥ 8 chars). |
| GET | `/api/auth-methods` | `{oidc, ldap}` booleans — which SSO options are enabled (public). |
| GET | `/api/oidc/login` | Starts the OIDC auth-code flow (redirect). |
| GET | `/api/oidc/callback` | OIDC redirect target; mints a session. |
| POST | `/api/2fa/setup` | Returns `{secret, uri}` (otpauth URI). Not persisted until enabled. |
| POST | `/api/2fa/enable` | `{secret, code}`. Verifies and turns on 2FA. |
| POST | `/api/2fa/disable` | Turns off 2FA. |

## Hosts

Host object (fields depend on `type`): `{id, type, domains[], upstream{scheme,host,port}, upstreams[], redirect{httpCode,targetScheme,targetHost,preservePath}, staticRoot, certMode, certId, forceSsl, enabled, accessListId, options{...}}`.

`type` ∈ `proxy | redirect | dead | static`. `certMode` ∈ `auto | custom | none`. `options` carries the typed advanced settings (headers, timeouts, hsts, rateLimit, forwardAuth, clientCert, blockExploits, blockIndexing, compression, …).

| Method | Path | Notes |
|---|---|---|
| GET | `/api/hosts` | List all hosts. |
| POST | `/api/hosts` | Create; returns the host with its `id`. |
| PUT | `/api/hosts/{id}` | Full replace. |
| DELETE | `/api/hosts/{id}` | |
| GET | `/api/health` | Backend health for pooled upstreams: `[{target, up, lastErr}]`. |

## Access lists

Object: `{id, name, satisfy, passAuth, rules[], users[]}`. A rule sets exactly one of `cidr`, `host` (dynamic DNS) or `country` (GeoIP), plus `action` (`allow|deny`). Users: `{username, password?}` — password write-only, omit to keep existing.

| Method | Path |
|---|---|
| GET | `/api/access-lists` |
| POST | `/api/access-lists` |
| PUT | `/api/access-lists/{id}` |
| DELETE | `/api/access-lists/{id}` |

## Streams

Object: `{id, listenPort, listenPortEnd?, protocol, forwardHost, forwardPort, allowedCidrs[], sendProxyProtocol?, acceptProxyProtocol?, terminateTls?, certId?, sniRoutes[], enabled}`. `protocol` ∈ `tcp | udp | both`.

| Method | Path |
|---|---|
| GET | `/api/streams` |
| POST | `/api/streams` |
| PUT | `/api/streams/{id}` |
| DELETE | `/api/streams/{id}` |

## Certificates

| Method | Path | Notes |
|---|---|---|
| GET | `/api/certs` | Managed (ACME) cert status: `[{domain, status, notAfter, lastError, errorAt}]`. |
| GET | `/api/custom-certs` | Uploaded certs (key material never returned). |
| POST | `/api/custom-certs` | `{name, certPem, keyPem}`. |
| PUT | `/api/custom-certs/{id}` | Replace PEM in place (hosts keep referencing it). |
| DELETE | `/api/custom-certs/{id}` | Blocked if a host uses it. |
| POST | `/api/custom-certs/self-signed` | `{name, domains[], days}`. Generates + stores. |
| POST | `/api/custom-certs/from-file` | `{name, certPath, keyPath}`. Reads server-local files. |

## Settings

`GET /api/settings` returns the closed key set; `PUT /api/settings` merges a subset (unknown keys `400`). All values are strings.

Keys: `acme_email`, `acme_staging` (`"1"`/`"0"`), `acme_ca_url`, `acme_dns_provider`, `acme_dns_config`, `notify_url`, `default_site` (`404|html|redirect`), `default_site_value`, `ban_enabled`, `ban_threshold`, `ban_window_sec`, `ban_duration_sec`, `oidc_*`, `ldap_*`.

`POST /api/notify-test` fires a test webhook alert.

## Tokens

| Method | Path | Notes |
|---|---|---|
| GET | `/api/tokens` | List (no secret). |
| POST | `/api/tokens` | `{name}` → returns `{id, name, token}`; **`token` shown once**. |
| DELETE | `/api/tokens/{id}` | Revoke. |

## System / ops

| Method | Path | Notes |
|---|---|---|
| GET | `/api/config` | Effective (applied) routing table: `[{domain, type, target, wildcard}]`. |
| GET | `/api/logs?n=200` | Recent access-log lines (newest first), each the JSON log record. Max `n`=2000. |
| GET | `/api/backup` | Streams a `tar.gz` (SQLite snapshot + cert tree). |
| POST | `/api/restore` | Body = a backup `tar.gz`. Replaces everything atomically. |
| POST | `/api/import` | Declarative config: `{accessLists[], hosts[], streams[]}`. Additive; returns counts. |
| GET | `/metrics` | Prometheus exposition (unauthenticated; gate the port). Counters: `quicgate_requests_total`, `quicgate_responses_total{class}`, `quicgate_response_bytes_total`. |

## Example: create a proxy host via token

```bash
TOKEN=qg_xxxxxxxx
curl -X POST https://quicgate.example.com/api/hosts \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "type": "proxy",
    "domains": ["app.example.com"],
    "upstream": {"scheme": "http", "host": "10.0.0.5", "port": 8080},
    "certMode": "auto",
    "forceSsl": true,
    "enabled": true,
    "options": {"hsts": {"enabled": true, "maxAge": 15552000}}
  }'
```
