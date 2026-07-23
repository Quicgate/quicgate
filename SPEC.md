# quicgate

A single-binary reverse proxy manager in Go. The feature set and UI flow of Nginx Proxy Manager, but the proxy engine is native Go (no nginx, no Traefik), with HTTP/3 (QUIC) out of the box and every "advanced" option expressed as a structured, typed setting instead of a free-text config blob.

## Goals

- Full functional parity with Nginx Proxy Manager (v2.12.x feature set).
- Everything NPM users reach for in the "Advanced" custom-nginx box becomes a first-class form field. There is deliberately NO raw-config escape hatch: if an option is missing, it gets added to the engine as a typed option.
- One binary, one SQLite file. Config changes apply instantly (atomic in-memory swap, no reload).
- UI: dark "Console" design language (near-black + lime, Geist), vanilla JS, no build step, embedded via go:embed.

## Non-goals (explicitly out)

- Kubernetes ingress, docker label auto-discovery, clustering. This fronts a homelab.
- WAF beyond NPM's "block common exploits" level.
- Response body rewriting (nginx sub_filter). Revisit only if a real need appears.

## Engine: load-bearing packages

| Concern | Package | Notes |
|---|---|---|
| HTTP/3 + QUIC | github.com/quic-go/quic-go (http3.Server) | Same lib Caddy/Traefik use. Shares the http.Handler with the TCP listeners. |
| HTTP/1.1 + HTTP/2 | net/http | Stdlib. |
| Proxying | net/http/httputil.ReverseProxy | Stdlib. Streaming, websockets, h2 upstreams work out of the box. |
| Certificates | github.com/caddyserver/certmagic | ACME issue/renew, HTTP-01 / TLS-ALPN-01 / DNS-01, OCSP stapling, on-demand TLS. |
| DNS-01 providers | libdns (incl. libdns/transip) | Wildcards via the existing TransIP key. |
| Storage | modernc.org/sqlite | Pure Go, no CGO, builds FROM scratch. |
| Compression | stdlib gzip + github.com/klauspost/compress (zstd) | Response compression toggle. |

Routing core: `map[hostname]*HostConfig` behind an `atomic.Pointer`, rebuilt from SQLite on every mutation. Lookup is exact match then wildcard. Port 80 handler does ACME HTTP-01 + force-HTTPS redirects.

## Feature parity matrix (NPM -> quicgate)

Legend: M1/M2/M3 = milestone.

### Proxy Hosts

| NPM feature | quicgate | Milestone |
|---|---|---|
| Multiple domain names per host | Host list, wildcard support | M1 |
| Forward scheme http/https, host, port | Upstream config | M1 |
| Websockets support (toggle) | Always on (httputil handles it); no toggle needed | M1 |
| Block common exploits (toggle) | Request filter middleware (SQLi/traversal/bad UA patterns) | M2 |
| Cache assets (toggle) | Static asset cache middleware (memory + disk, by extension) | M3 |
| Access list assignment | Access list reference per host | M2 |
| SSL: cert selection | Pick managed (ACME) or uploaded cert, or "auto" | M1 |
| SSL: Force SSL | 80 -> 443 redirect per host | M1 |
| SSL: HTTP/2 support toggle | Always on; per-host min protocol setting instead | M1 |
| SSL: HSTS + subdomains | Typed HSTS options (max-age, includeSubDomains, preload) | M1 |
| Custom locations (path -> other upstream) | Path routes per host; every host-level option overridable per path | M2 |
| Advanced free-text nginx config | Replaced by structured options (see below) | M1/M2 |

### Redirection Hosts

| NPM feature | quicgate | Milestone |
|---|---|---|
| Domains, forward scheme+domain | Redirect host type | M2 |
| HTTP code 300/301/302/307/308 | Typed enum | M2 |
| Preserve path toggle | Toggle | M2 |
| SSL options | Same TLS block as proxy hosts | M2 |

### Streams

| NPM feature | quicgate | Milestone |
|---|---|---|
| TCP port forward | net.Listener + io.Copy pump | M2 |
| UDP port forward | net.PacketConn relay with session map | M2 |

### 404 Hosts (dead hosts)

Host type that serves a branded 404 with valid TLS. M2.

### Default site (Settings)

What unmatched hostnames get: 404 page / congratulations page / redirect / custom HTML. M2.

### SSL Certificates screen

| NPM feature | quicgate | Milestone |
|---|---|---|
| Let's Encrypt via HTTP challenge | certmagic HTTP-01 | M1 |
| DNS challenge (wildcards) | certmagic DNS-01 via libdns; TransIP provider wired in | M2 |
| Upload custom certificate | PEM upload, stored encrypted at rest | M2 |
| Renewal, expiry overview | certmagic auto-renew; UI lists cert status/expiry | M1 |

### Access Lists

| NPM feature | quicgate | Milestone |
|---|---|---|
| Basic auth users | bcrypt users per list | M2 |
| Allow/deny CIDR rules | Ordered rule list | M2 |
| Satisfy any/all | Enum | M2 |
| Pass auth to upstream | Toggle (forward or strip Authorization) | M2 |

### Users, audit log

| NPM feature | quicgate | Milestone |
|---|---|---|
| Multi-user + roles/visibility | Admin + limited users | M3 |
| Audit log of all changes | Append-only audit table, UI viewer | M3 |

M1 ships with single admin login (bcrypt + session cookie).

## Structured "advanced" options

This is the replacement for NPM's raw nginx textarea. Grouped, typed, validated server-side, JSON in one `options` column. Every option exists at host level and can be overridden per custom location.

**Upstream**
- Preserve incoming Host header / override with fixed value
- Skip TLS verification for https upstreams (self-signed backends)
- Upstream SNI override
- Timeouts: dial, response header, idle (durations)
- Max request body size
- Response buffering on/off (off = pure streaming, SSE-safe)

**Request**
- Header rules: ordered set/add/remove with value templating (client IP, host, scheme)
- X-Forwarded-For/Proto/Host handling + trusted proxy CIDRs (real IP)
- Path rewrite: strip prefix, add prefix, regex rewrite

**Response**
- Header rules: ordered set/add/remove
- Hide upstream headers (e.g. X-Powered-By, Server)
- Compression: off/gzip/zstd + minimum size
- Custom error pages (per status code, HTML upload)

**Security**
- Rate limit: requests/sec + burst, per client IP, per host
- Max concurrent connections per host
- Block common exploits toggle (shared filter, versioned patterns)

**TLS (per host)**
- Min TLS version
- HTTP/3 advertise toggle (Alt-Svc)
- HSTS block (max-age, includeSubDomains, preload)

Options render as form controls in a tabbed "Advanced" panel per host. Unknown/removed keys are rejected on save, never silently dropped.

## Data model (SQLite)

- `hosts` (id, type: proxy|redirect|stream|dead, domains JSON, upstream JSON, cert_id, access_list_id, options JSON, enabled)
- `locations` (id, host_id, path, match type, upstream JSON, options JSON)
- `certs` (id, type: acme|custom, domains, PEM refs, meta)
- `access_lists` (id, name, satisfy, pass_auth) + `access_list_users`, `access_list_rules`
- `users` (id, email, bcrypt, role, disabled)
- `audit_log` (id, ts, user_id, action, entity, before JSON, after JSON)
- `settings` (key, value)

## Milestones

- **M1 (usable core):** proxy hosts CRUD + UI, certmagic HTTP-01 auto-TLS, HTTP/1.1+2+3 serving, force-SSL, HSTS, header rules, timeouts, body size, streaming, single admin login. Success test: add a host in the UI, cert issues automatically, site serves over HTTP/3.
- **M2 (NPM parity):** access lists, block-exploits filter, rate limiting, custom locations, redirection hosts, dead hosts, default site, TCP/UDP streams, DNS-01 wildcards (TransIP), custom cert upload, error pages, compression.
- **M3 (polish):** multi-user + audit log, static asset cache, Prometheus /metrics, config export/import (JSON).

## Deployment

Ship as a single container: FROM scratch + static binary + CA bundle; one volume for the SQLite db + certmagic storage. Needs 80/443 (TCP) and 443 (UDP, HTTP/3) published. Can run alongside NPM/Pangolin on different ports until trusted.
