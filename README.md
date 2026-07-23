# quicgate

<img src="brand/logo-full.svg" alt="quicgate" height="72">

Single-binary reverse proxy manager. The workflow of Nginx Proxy Manager, but the engine is native Go: HTTP/1.1, HTTP/2 and HTTP/3 (QUIC via quic-go), automatic Let's Encrypt certificates (certmagic), and every "advanced" option as a typed, validated setting instead of a free-text nginx blob. Config changes apply instantly, no reloads.

See [SPEC.md](SPEC.md) for the NPM feature parity matrix, [ROADMAP.md](ROADMAP.md) for the (now-completed) issue-tracker-mined feature list, and [API.md](API.md) for the REST API reference. Interactive Swagger UI is served at `/docs.html` (OpenAPI spec at `/openapi.yaml`).

## Features

- **Hosts**: proxy, redirection (301/302/307/308), 404/dead, and static-file hosts. Load-balancing upstream pools with active health checks. Typed advanced options (headers, timeouts, rewrites, buffering, body limits) — no free-text config.
- **TLS**: automatic Let's Encrypt (HTTP-01), DNS-01 wildcards (TransIP), custom cert upload, self-signed generation, cert-from-file, custom ACME CAs (ZeroSSL/step-ca), mTLS client certs, per-host min-version + HSTS, HTTP/3.
- **Security**: access lists (CIDR / dynamic-DNS hostname / GeoIP-country rules + basic auth, satisfy any/all), forward-auth (Authelia/Authentik/Keycloak), rate limiting, block-common-exploits, auto-ban (fail2ban-style), noindex, gzip.
- **Streams (TCP/UDP)**: port forwards with source whitelists, PROXY protocol (send + accept), TLS termination, SNI-based passthrough routing, port ranges. Automatic UPnP router forwards.
- **Ops**: one-click backup/restore, declarative JSON import, live access-log viewer, Prometheus `/metrics`, effective-config viewer, certificate renewal visibility + webhook alerts.
- **Admin auth**: local password + forced first change, 2FA/TOTP, API tokens, optional OIDC and LDAP (both additive).

Config changes apply via an atomic in-memory swap — the running config can never drift from the stored config.

## Run (dev)

```
go run . 
```

Environment:

| Var | Default | Meaning |
|---|---|---|
| QG_DATA | ./data | SQLite db + certmagic storage |
| QG_HTTP | :80 | plain HTTP listener (ACME + redirects) |
| QG_HTTPS | :443 | TLS listener, TCP and UDP (HTTP/3) |
| QG_ADMIN | :81 | management UI/API |
| QG_ACME_EMAIL | (empty) | ACME account email |
| QG_ACME_STAGING | | set to 1 for the Let's Encrypt staging CA |
| QG_TLS | | set to `off` for a dev run without TLS/QUIC listeners |
| QG_UPNP | | set to 1 to auto-manage router port forwards via UPnP IGD |

Most settings (ACME email/staging/CA, DNS provider, notify webhook, default site, auto-ban, OIDC/LDAP) are also editable live in the Settings page and stored in the database. Optional files under `QG_DATA`: `GeoLite2-Country.mmdb` enables GeoIP access rules.

First login: `admin@example.com` / `changeme` (password change forced).

## Run (docker)

```
docker build -t quicgate .
docker run -d -p 80:80 -p 443:443/tcp -p 443:443/udp -p 81:81 -v quicgate-data:/data quicgate
```
