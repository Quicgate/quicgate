# Changelog

All notable changes to quicgate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-23

First public release. quicgate is a single-binary reverse-proxy manager: the
Nginx Proxy Manager workflow on a native Go engine (HTTP/1.1/2/3), automatic
Let's Encrypt certificates, and every advanced option as a typed, validated
setting instead of a free-text config blob. It has been running a ~50-host
homelab in production.

### Hosts & TLS
- Proxy, redirection (301/302/307/308), 404 and static-file hosts; wildcard
  domains; load-balanced upstream pools with active health checks; custom
  locations (path prefix → upstream) and path rewrites.
- Automatic Let's Encrypt (HTTP-01), DNS-01 wildcards, custom cert upload,
  self-signed generation, custom ACME CAs, mTLS client certs, per-host minimum
  TLS version, HSTS, hardened AEAD-only cipher defaults, HTTP/3 with a per-host
  opt-out that clears the browser's cached Alt-Svc hint.

### Security & access
- Access lists: ordered CIDR / dynamic-DNS / GeoIP-country rules **plus
  per-rule HTTP-method scoping**, basic auth, satisfy any/all.
- CORS preflight requests bypass the auth gate (the real request stays gated).
- Forward-auth (Authelia/Authentik/Keycloak), per-IP rate limiting,
  block-common-exploits, bad-bot blocking, fail2ban-style auto-ban.
- Admin hardening: strict CSP, same-origin CSRF guard (bearer-exempt),
  server-side forced first-password change, `SameSite=Strict`/`Secure`/
  `HttpOnly` cookies, TOTP 2FA, API tokens, optional OIDC and LDAP login.

### Streams & router
- TCP/UDP L4 forwards with source whitelists, PROXY protocol v1/v2, TLS
  termination, SNI passthrough routing, port ranges.
- Router port-forward management over UPnP IGD (self-healing after reboots).

### Ops
- JSON access logs with a built-in per-host and system-wide viewer, Prometheus
  `/metrics` (behind auth, per-host), one-click backup/restore, declarative
  JSON import, effective-config viewer, certificate renewal alerts.
- Runs fully offline: fonts and Swagger UI are vendored, no runtime CDN calls.
- Version is stamped into the binary and shown in the UI (`/api/version`).

[1.0.0]: https://github.com/maferick/quicgate/releases/tag/v1.0.0
