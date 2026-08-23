# Changelog

All notable changes to quicgate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.8.0] - 2026-08-23

### Added
- **Per-path identity providers.** A `mode: oidc` path rule can now name its
  own provider and policy instead of inheriting the host's, so one host can
  gate `/staff` with the company IdP and `/partner` with another, or use a
  separate app registration per URL on the same IdP. Every provider redirects
  back to the one callback path; the signed state cookie records which login
  is in flight, so the gate that started it finishes it.
- **The admin login can reuse a provider entry.** Settings gains an identity
  provider picker (`admin_oidc_provider_id`) listing the same providers the
  hosts use, instead of repeating issuer, client id and secret in its own
  fields. Those fields remain the fallback, so existing setups are untouched,
  and the admin allow-list stays separate either way.

### Security
- **SSO sessions are now bound to the issuing provider.** They were bound to
  the host only, so once a host could reference two providers, a session
  obtained from the less trusted one satisfied a path gated by the more
  trusted one: get an account wherever you can, walk in everywhere. Sessions
  carry the provider id and a gate accepts only its own. Existing sessions do
  not carry it and are re-authenticated once.
- Deleting a provider is refused while a path rule or the admin login still
  references it, matching the existing check for hosts.

### Fixed
- The host modal's OIDC provider pickers were empty unless the Access Lists
  page had been opened first, so saving a host from that state silently
  dropped the provider it was using. The hosts page loads providers itself.

[1.8.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.8.0

## [1.7.2] - 2026-08-23

### Security
- **Admin OIDC login admitted anyone the provider would authenticate.** With
  `oidc_allowed_emails` empty, `emailAllowed()` returned true for every
  address, so enabling admin SSO against a tenant you do not exclusively
  control handed full proxy administration to every account in it. An external
  identity now needs either a local account with the same address or an
  explicit allow-list entry; an empty list matches nobody. Password login is
  unaffected, so this cannot lock anyone out.
- **Admin OIDC ignored `email_verified`.** The claim was parsed and never
  read. A provider that lets users choose their own address could therefore be
  used to claim an administrator's address. A login is now refused when the
  provider explicitly marks the address unverified.
- **Any directory user could administer the proxy over LDAP.** A successful
  bind was treated as authorisation, so every account in a corporate directory
  held root over the ingress. Binding now only proves the password;
  administering also requires a local account or an entry in the new
  `ldap_allowed_users` list.
- **LDAP used filter escaping on a distinguished name.** `EscapeFilter`
  escapes search-filter metacharacters and leaves `,`, `=`, `+` and friends
  alone, so a crafted username could restructure the DN it was spliced into.
  Now `EscapeDN`, as the value's context requires.
- **LDAP binds refuse plaintext transport.** `ldap://` sent the admin password
  in clear text; `ldaps://` is now required, with a 5s dial and 10s operation
  timeout so a hung directory cannot pin a login request.
- **Restore could be used as a decompression bomb.** The upload limit bounded
  the compressed body only, so a few megabytes of zeroes could expand without
  bound and fill the data volume. Expansion is now capped at 2 GiB, and
  archives carrying duplicate or non-regular (symlink, device) members are
  rejected.
- Admin sessions minted by OIDC now get the same cookie treatment as password
  logins: `SameSite=Strict` and `Secure` on HTTPS, instead of `Lax` and never
  `Secure`. Entropy failures when minting the session id are no longer ignored.

### Fixed
- `/api/me` returned 500 for an approved OIDC/LDAP identity with no local
  database row, breaking the UI right after a successful external login. It
  now reports the session identity and no local 2FA.
- An LDAP user who also has a local account keeps that local identity on the
  session, so the forced password change, 2FA and the profile page resolve to
  the real account instead of an `ldap:`-prefixed stand-in.

[1.7.2]: https://github.com/Quicgate/quicgate/releases/tag/v1.7.2

## [1.7.1] - 2026-08-23

### Security
- **Path traversal could walk out of a public path rule.** A request for
  `/public/../admin` matched a `public` auth rule on its raw path, while an
  upstream that resolves dot segments (nginx, Apache, IIS, most frameworks)
  served `/admin` — bypassing the host's access list, forward auth or SSO.
  Any path containing a `.` or `..` segment is now refused with 400 before it
  reaches a gate, a path rule, a custom location or an upstream. Whole
  segments only, so `/.well-known/acme-challenge/...` and `/file.tar.gz` are
  unaffected. Encoded forms (`%2e%2e`) are covered, since matching happens on
  the decoded path.
- **Forward-auth hosts passed client-supplied identity headers.** The headers
  listed under *Copy response headers upstream* were only overwritten when the
  auth server returned a non-empty value, so a 2xx response that omitted
  `Remote-User` let the client's own `Remote-User` reach the upstream. Those
  headers are now stripped from the inbound request before the auth subrequest
  and before the upstream sees it. (OIDC hosts already stripped them.)
- **SSO session cookies were not marked Secure behind a TLS-terminating
  proxy.** `Secure` was set from `r.TLS` alone, so with TLS terminating on a
  load balancer in front of quicgate the session cookie could ride a plain
  HTTP hop. It now honours `X-Forwarded-Proto`, as the OIDC redirect URI
  scheme does — which also fixes redirect-URI mismatches in that deployment.
- **Unthrottled admin login.** A wrong password cost a flat 400ms and nothing
  else, and the six-digit TOTP code had no limit at all, so an attacker
  holding the password could walk the code space. Failed logins are now
  counted per client IP, with a 15-minute lockout after 10 failures in 15
  minutes, covering password, LDAP and TOTP failures alike.
- **Credentials echoed by the settings API.** `GET /api/settings` returned the
  admin OIDC client secret and the DNS provider config (which holds a private
  key) in cleartext to any session or API token, putting them in the browser
  and in any exported HAR. Both are masked on read; sending the mask back
  keeps the stored value.

### Fixed
- The OIDC login callback is now always routed to the SSO gate. A host that
  gated only some paths with SSO sent the browser to the IdP and then handed
  the redirect back to whichever path rule matched `/.qg/oidc/callback`, so
  the session was never minted and the user looped through login.
- A login is refused when the IdP explicitly marks the address unverified
  (`email_verified: false`), so a self-set address cannot satisfy an
  allowed-domains policy.
- The post-login redirect target rejects backslashes and CR/LF in addition to
  protocol-relative paths.

[1.7.1]: https://github.com/Quicgate/quicgate/releases/tag/v1.7.1

## [1.7.0] - 2026-08-23

### Added
- **Built-in OIDC SSO.** A proxy host can now require an OpenID Connect login
  served by quicgate itself, replacing the Pomerium/Authelia/oauth2-proxy
  sidecar for the common case. Identity providers (Keycloak, Entra ID,
  Authentik, any spec-compliant IdP) are defined once under **Access Lists ->
  Identity providers** and referenced per host; quicgate runs the auth-code
  flow with PKCE and a nonce, keeps a stateless HMAC-signed session cookie
  that is bound to the exact host it was minted for, and enforces a per-host
  policy of allowed emails, domains and/or groups (from a configurable groups
  claim). The identity can be passed upstream as `Remote-User` /
  `Remote-Email` / `Remote-Groups`; inbound copies of those headers are
  always stripped, on public paths too, so they can never be spoofed through
  quicgate. Gated hosts reserve `/.qg/oidc/callback` (the redirect URI to
  register at the IdP) and `/.qg/oidc/logout`. IdP discovery is lazy and
  cached, so config reloads never block on the IdP, and a host whose
  provider was deleted fails closed with 403. Providers are managed via
  `/api/oidc-providers` (client secret masked in responses; an empty secret
  on update keeps the stored one) and included in backups.
- **Path authentication.** A proxy host's access list and forward auth used to
  gate the whole host; they can now be overridden per URL. Each rule is a path
  (prefix or exact), a mode (`public`, a named access list, the host's
  forward auth, or the host's OIDC SSO) and optional HTTP verbs, and the longest matching path wins.
  Anything matching no rule keeps the host's own gate. This covers the case a
  reverse proxy in front of SSO always runs into: a licensing callback, webhook
  receiver or health probe that has to answer without credentials while the
  rest of the host stays behind authentication. Rate limits, bad-bot and
  exploit filters remain host-wide, so a public path is still protected from
  abuse. Editable under **Security -> Path authentication** in the host modal;
  stored as `options.authRules`. A rule naming an access list that no longer
  exists falls back to the host's gate instead of opening the path, and the API
  rejects such a reference on write.
- **Built-in guides.** The Help page now opens with five markdown guides
  (getting started, configuration reference, access control & SSO, Docker
  labels, streams & port forwards) rendered by a small vanilla markdown
  renderer, embedded in the binary and fully offline. The same files live in
  `web/docs/` on GitHub, and the README slimmed down to a pitch that links to
  them.
- The Proxy Hosts table links each domain to the site itself (new tab), with
  the scheme taken from the host's certificate mode. Wildcard domains stay
  plain text since they have no single address to visit.

[1.7.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.7.0

## [1.6.1] - 2026-08-23

### Changed
- Dependency updates: `klauspost/compress` 1.19.1 -> 1.19.2 (gzip/zstd
  compression), `golang.org/x/crypto` 0.54.0 -> 0.55.0 and
  `modernc.org/sqlite` 1.55.0 -> 1.56.0 (the config store), plus the
  indirect bumps they pull in. No functional changes.

[1.6.1]: https://github.com/Quicgate/quicgate/releases/tag/v1.6.1

## [1.6.0] - 2026-08-04

### Added
- The Proxy Hosts table now shows backend health inline: a host whose
  upstream fails its health probe gets a red-tinted row and a `down` badge
  next to the upstream. Pool hosts keep their `N/N up` badge and pick up
  the same row tint when part of the pool is down. Uses the same health
  data as the Overview donut, refreshed every time the page is opened.

### Fixed
- HTTP/3 requests were proxied upstream as `Transfer-Encoding: chunked`:
  quic-go reports "unknown length" for bodyless requests, so every browser
  GET arriving over h3 was forwarded chunked, which strict upstreams (for
  example lighttpd) reject with 400 Bad Request before routing. Bodyless
  GET/HEAD requests are now normalized to an explicit empty body on both
  the host proxy and per-location proxies; POST/PUT bodies stream as
  before.

[1.6.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.6.0

## [1.5.3] - 2026-07-30

### Fixed
- **IPv6 literal upstreams and stream targets.** Addresses were built as
  `host:port`, which produces `2001:db8::1:8080` for an IPv6 literal — an
  address `net.Dial` rejects ("too many colons in address"). Health checks
  therefore marked every IPv6-literal backend permanently **down**, and IPv6
  stream forwards (and SNI-route targets) failed outright. All upstream, pool,
  location, stream and SNI addresses are now built with `net.JoinHostPort`, so
  they are correctly bracketed (`[2001:db8::1]:8080`). Hostnames that resolve to
  AAAA records were unaffected; only literal IPv6 addresses were.

[1.5.3]: https://github.com/Quicgate/quicgate/releases/tag/v1.5.3

## [1.5.2] - 2026-07-30

### Changed
- Dependency updates: `quic-go` 0.60.0 -> 0.61.0 (the HTTP/3 engine) and
  `modernc.org/sqlite` 1.54.0 -> 1.55.0 (the config store). No functional
  changes.

[1.5.2]: https://github.com/Quicgate/quicgate/releases/tag/v1.5.2

## [1.5.1] - 2026-07-24

### Changed
- Project moved to its own GitHub organization: **`Quicgate/quicgate`**. The
  container image is now **`ghcr.io/quicgate/quicgate`** (the old
  `ghcr.io/maferick/quicgate` path stops receiving updates; repoint your
  `image:` to the new one). No functional changes.

[1.5.1]: https://github.com/Quicgate/quicgate/releases/tag/v1.5.1

## [1.5.0] - 2026-07-24

### Added
- **Overview dashboard**: a new landing page with an at-a-glance summary —
  listeners, config counts (hosts by type, certificates, streams, access
  lists), health donuts (upstreams up/down, certificates issued/pending/failed,
  hosts by type), feature flags (HTTP/3, UPnP, auto-ban, GeoIP, forward-auth,
  OIDC, LDAP, Docker), and providers. One `GET /api/overview` call; vanilla
  inline-SVG donuts, no chart library.
- **Real client IP behind a trusted proxy** (Traefik #3097): when quicgate sits
  behind Cloudflare or another load balancer, set trusted-proxy CIDRs and a
  header (Settings) so access lists, GeoIP, rate limits and logs use the real
  client IP. A rightmost-untrusted `X-Forwarded-For` walk defeats client
  spoofing of the header.
- **Sticky sessions** (Traefik #1207/#1035): a per-host cookie affinity across a
  load-balanced upstream pool, so a client keeps hitting the same backend
  (the cookie carries an opaque id, never the upstream address).
- **Maintenance mode** (Traefik #3520): a per-host toggle that serves a 503
  "under maintenance" page (with `Retry-After` and an optional custom body)
  instead of proxying.
- **Response caching** (Traefik #878): a per-host TTL that caches cacheable
  GET/HEAD responses in memory (honouring `Cache-Control`, skipping `Set-Cookie`
  and authenticated requests), with an `X-Cache: HIT/MISS` header.

These four came from mining Traefik's most-reacted enhancement requests for
proxy-layer features that fit a homelab.

[1.5.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.5.0

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

[1.4.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.4.0

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

[1.3.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.3.0

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

[1.2.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.2.0

## [1.1.1] - 2026-07-23

### Added
- In-app **Help & FAQ** page (the `?` icon in the top bar): common recipes and
  concepts (access-list evaluation, the GET-from-everywhere pattern, hosts vs
  streams, certs/HTTP-3, admin-port safety, API tokens). Embedded, works offline.

[1.1.1]: https://github.com/Quicgate/quicgate/releases/tag/v1.1.1

## [1.1.0] - 2026-07-23

### Added
- **Streams can reuse an access list as their source filter** instead of
  retyping CIDRs — pick an access list on the stream, and its allow CIDR/host
  rules become the source allowlist (only IP rules apply at L4).

### Changed
- Method-scoped access rules now use clickable **HTTP-verb chips** in the UI
  instead of a free-text box (keyboard-accessible; none selected = all verbs).

[1.1.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.1.0

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

[1.0.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.0.0
