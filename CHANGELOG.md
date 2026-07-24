# Changelog

All notable changes to quicgate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.5.0] - 2026-07-24

### Added
- **Overview dashboard**: a new landing page with an at-a-glance summary —
  listeners, config counts (hosts by type, certificates, streams, access
  lists), health donuts (upstreams up/down, certificates issued/pending/failed,
  hosts by type), feature flags (HTTP/3, UPnP, auto-ban, GeoIP, forward-auth,
  OIDC, LDAP, Docker), and providers. One `GET /api/overview` call; vanilla
  inline-SVG donuts, no chart library.

[1.5.0]: https://github.com/maferick/quicgate/releases/tag/v1.5.0

## [1.4.0] - 2026-07-24

### Added
- **GeoIP status on the Settings page**: shows whether the GeoLite2-Country
  database is loaded (with its type and build date, or the exact expected path
  and error when missing), a **Recheck** button that re-opens the file with no
  restart, and a **test-an-IP** lookup so you can confirm country resolution
  actually works.
- Country access rules are now chosen from a **country picker** (the full list
  of ISO 3166-1 countries by name) instead of a free-text code, and the
  access-list editor warns when a country rule is used while GeoIP is not loaded.
  Country codes are also validated server-side.

### API
- `GET /api/geoip/status`, `POST /api/geoip/reload`, `GET /api/geoip/lookup?ip=`.

[1.4.0]: https://github.com/maferick/quicgate/releases/tag/v1.4.0

## [1.3.0] - 2026-07-24

### Added
- **Multiple Docker hosts**: the label provider can watch several daemons at
  once. Configure a JSON list of endpoints (`QG_DOCKER_ENDPOINTS`, or the
  **Docker hosts** box on the Docker page), each with a name, a connection (a
  local socket path or `tcp://host:port`, e.g. a read-only socket proxy), and
  the address where that host's published ports are reachable. The Docker page
  shows each host's connection state and labels every container with its host.
- The Docker client now speaks `tcp://` endpoints in addition to unix sockets.

### Changed
- **Simpler connect model**: quicgate now always reaches a container at the
  Docker host's address on its published port (a `network_mode: host` container
  at that port directly). The `auto` / `network` / `published` connect-mode and
  the shared-network container-IP path are gone; `quicgate.port` still names the
  container's internal port, so publish the port you want routed. Removes the
  `docker_connect_mode` and `docker_host_address` settings (endpoints carry the
  address now).

[1.3.0]: https://github.com/maferick/quicgate/releases/tag/v1.3.0

## [1.2.0] - 2026-07-24

### Added
- **Docker label provider** (opt-in via `QG_DOCKER=1`): derive proxy hosts and
  TCP/UDP streams from container labels — Traefik's provider idea with a flat
  label set, no router/service/middleware graph.
  - Labels: `quicgate.enable`, `quicgate.host`, `quicgate.port`,
    `quicgate.exclude-ports`, `quicgate.scheme`, `quicgate.tls-skip-verify`,
    `quicgate.tls`, `quicgate.access-list`, and `quicgate.streams` (raw L4
    forwards). Stream ports are excluded from web-port auto-detection, so a
    container with a web port and a game/DB port needs no manual excludes.
  - Optional `QG_DOCKER_DOMAIN` derives the hostname from the container name.
    Access lists are reused by name. A container can be HTTP-only, streams-only,
    or both.
  - `auto` / `network` / `published` connect-modes resolve the upstream address
    per container, so it works whether quicgate runs on a bridge network or
    `network_mode: host`.
  - Manual hosts always win a naming conflict; derived routes are never
    persisted (re-derived from live containers). A **Docker** page shows every
    container with the exact reason it is or isn't routed, plus one-click
    **Convert to host** to graduate a container to editable configuration.
  - Read-only Docker client over the socket (list / inspect / events), no
    third-party SDK, zero new dependencies.

[1.2.0]: https://github.com/maferick/quicgate/releases/tag/v1.2.0

## [1.1.1] - 2026-07-23

### Added
- In-app **Help & FAQ** page (the `?` icon in the top bar): common recipes and
  concepts (access-list evaluation, the GET-from-everywhere pattern, hosts vs
  streams, certs/HTTP-3, admin-port safety, API tokens). Embedded, works offline.

[1.1.1]: https://github.com/maferick/quicgate/releases/tag/v1.1.1

## [1.1.0] - 2026-07-23

### Added
- **Streams can reuse an access list as their source filter** instead of
  retyping CIDRs — pick an access list on the stream, and its allow CIDR/host
  rules become the source allowlist (only IP rules apply at L4).

### Changed
- Method-scoped access rules now use clickable **HTTP-verb chips** in the UI
  instead of a free-text box (keyboard-accessible; none selected = all verbs).

[1.1.0]: https://github.com/maferick/quicgate/releases/tag/v1.1.0

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
