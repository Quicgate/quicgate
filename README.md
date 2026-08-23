<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo-full-dark.svg">
    <img src="brand/logo-full.svg" alt="quicgate" height="84">
  </picture>
</p>

<p align="center">
  <b>A complete Nginx Proxy Manager replacement in one Go binary.</b><br>
  NPM's point-and-click workflow &middot; native Go engine &middot; HTTP/1.1 + HTTP/2 + <b>HTTP/3 (QUIC)</b> &middot; instant reloads &middot; no nginx, no Traefik, no free-text config.
</p>

<p align="center">
  <a href="https://github.com/Quicgate/quicgate/releases"><img src="https://img.shields.io/github/v/release/Quicgate/quicgate?color=a3e635&label=release" alt="latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-a3e635" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/go-1.26-00ADD8?logo=go" alt="Go 1.26">
  <img src="https://img.shields.io/badge/container-ghcr.io%2Fquicgate%2Fquicgate-0b0e0f" alt="ghcr.io/quicgate/quicgate">
  <img src="https://img.shields.io/badge/image%20size-~25MB-a3e635" alt="image size">
</p>

---

**quicgate** exists because I loved Nginx Proxy Manager's workflow but not its internals, and loved Pangolin's engine but not its complexity. So: the NPM experience, rebuilt on a modern native-Go data plane, in a single `FROM scratch` container.

- **One process, one container, one SQLite file.** The proxy engine, ACME client, TCP/UDP streams, admin UI and REST API are one Go binary. No sidecar database, no config files to template, no nginx to reload.
- **HTTP/3 out of the box.** Every host is served over h1/h2/h3 with Alt-Svc advertisement (and a per-host opt-out that actively clears the browser's cached hint).
- **Typed options instead of config blobs.** NPM's "Advanced" nginx textarea is replaced by structured, validated settings: headers, timeouts, rewrites, buffering, rate limits, body limits, custom locations. If an option is missing, it gets added as a typed field, never as a text escape hatch.
- **Instant, atomic reloads.** Config changes swap the routing table in memory. The running config can never drift from the stored config.

## Quick start

```yaml
# docker-compose.yml
services:
  quicgate:
    image: ghcr.io/quicgate/quicgate:latest
    restart: unless-stopped
    network_mode: host      # engine owns 80/443 (tcp+udp), admin UI on 81
    environment:
      - QG_ACME_EMAIL=you@example.com
    volumes:
      - ./data:/data
```

```bash
docker compose up -d
```

Open `http://<host>:81`, sign in with `admin@example.com` / `changeme` (a password change is forced), add your first proxy host, and the certificate issues automatically. **Do not expose port 81 to the internet** — proxy it through quicgate itself with an access list, like any other host.

## Features

- **Hosts**: proxy, redirection (301/302/307/308), 404, and static-file hosts. Wildcard domains. Load-balanced upstream pools with active health checks and **cookie sticky sessions**, with backend health shown inline in the hosts table. Custom locations (path prefix to a different upstream), path rewrites (strip/add prefix, RE2 regex). Per-host **maintenance mode** (503 page) and **response caching**.
- **TLS**: automatic Let's Encrypt (HTTP-01), DNS-01 wildcards, custom cert upload, self-signed generation, custom ACME CAs (ZeroSSL, step-ca), mTLS client certificates, per-host minimum TLS version, HSTS, hardened AEAD-only cipher defaults.
- **Security**: access lists (ordered CIDR / dynamic-DNS hostname / GeoIP-country rules + basic auth, satisfy any/all), **built-in OIDC SSO** (quicgate runs the OpenID Connect login itself against Keycloak / Entra ID / Authentik — per-host allowed emails/domains/groups, identity passed upstream as `Remote-User`, no Authelia sidecar needed), forward-auth (Authelia / Authentik / Keycloak), per-IP rate limiting, block-common-exploits, bad-bot blocking, fail2ban-style auto-ban, search-engine noindex. **Path authentication**: per-URL overrides of the host's gate (longest match wins), so a licensing callback or webhook stays reachable without credentials while the rest of the host is behind an access list or SSO. **Real client IP** behind a trusted proxy (Cloudflare / another LB), so IP rules, GeoIP and rate limits still work.
- **Streams (TCP/UDP)**: L4 port forwards with source whitelists, PROXY protocol v1/v2 (send and accept), TLS termination, SNI-based passthrough routing, port ranges. Plus pure router port-forwards managed over **UPnP IGD** (quicgate keeps your router's forwards in sync, self-healing after reboots).
- **Dual-stack IPv4/IPv6**: listeners accept IPv6 clients out of the box, upstreams and stream targets can be IPv6 literals or AAAA hostnames, and access lists and trusted-proxy lists take IPv6 CIDRs (a bare address is treated as `/128`). Per-IP rate limiting, auto-ban and GeoIP country lookup all handle IPv6 clients the same as IPv4.
- **Docker labels**: opt a container in with `quicgate.enable=true` and quicgate derives its host (and TCP/UDP streams) from labels automatically — Traefik's provider idea without the router/service/middleware label soup. Reuses named access lists, works with a host-networked quicgate, and every derived route is visible (with the reason it is or isn't routing) on the Docker page. See [Docker labels](web/docs/docker.md).
- **Ops**: an at-a-glance **Overview dashboard**, JSON access logs with a built-in viewer (per-host and system-wide), Prometheus `/metrics` (global + per-host), one-click backup/restore, declarative JSON import, effective-config viewer, certificate renewal visibility with webhook alerts (ntfy/Gotify style).
- **Admin**: forced first-password change, TOTP 2FA, long-lived API tokens, optional OIDC and LDAP login (both additive, so a broken IdP can never lock you out), dark/light theme, Swagger UI at `/docs.html`.

## How it compares

| | **quicgate** | **Nginx Proxy Manager** | **Pangolin** |
|---|---|---|---|
| Data plane | native Go (net/http, quic-go) | nginx | Traefik |
| Deployment | **1 container, ~25MB, scratch** | 1 container (+optional db) | 3+ containers (pangolin, gerbil, traefik) |
| HTTP/3 (QUIC) | **yes, default, per-host toggle** | no | via Traefik config |
| Config model | **typed, validated options** | UI + free-text nginx snippets | UI + Traefik config |
| Reloads | instant atomic swap | nginx reload | Traefik provider push |
| ACME | HTTP-01, DNS-01 wildcards, custom CAs | certbot (many DNS plugins) | Let's Encrypt |
| TCP/UDP streams | yes + PROXY protocol + SNI routing + TLS termination | yes (basic) | via tunnels |
| WireGuard tunnels to remote sites | no | no | **yes (newt/olm), Pangolin's killer feature** |
| Identity-aware SSO on resources | **built-in OIDC SSO** + forward-auth | no | **built-in IdP/SSO** |
| Access lists (IP/CIDR) | yes + **GeoIP country + dynamic-DNS rules** | yes | yes |
| Auto-ban / abuse | built-in fail2ban-style + JSON logs for CrowdSec | no | CrowdSec integration |
| Router integration | **UPnP port-forward management** | no | no |
| Config from container labels | **yes — flat labels + streams, multi-host** | no | via Traefik labels |
| Admin 2FA | yes (TOTP) | no | yes |
| API | full REST + OpenAPI/Swagger + tokens | REST (undocumented) | REST |
| Metrics | Prometheus, per-host | no | via Traefik |
| Backup | one-click full backup/restore + JSON import | manual volume copy | manual |
| Maturity | **young, read the caveats** | battle-tested, huge community | growing fast |

**Choose NPM** if you want the most battle-tested option with years of community answers. **Choose Pangolin** if you need WireGuard tunnels to expose services on remote machines. **Choose quicgate** if you want one small container that replaces the whole stack with a modern engine — this repo runs my entire homelab ingress (~50 hosts) as its production deployment.

### Honest caveats

- Young project with one production deployment (mine), so expect rough edges. Issues welcome.
- No WireGuard tunneling — quicgate proxies to network-reachable upstreams only.
- Single admin user (with 2FA/OIDC/LDAP), no multi-tenant roles.

## Benchmarks

On an AMD Ryzen 7 9800X3D, one quicgate instance handles **~45,000 proxied requests/sec** to a local backend (loopback, no TLS) and **~180,000/sec** for cache hits, with a routing lookup costing ~9 ns and access lists adding no measurable overhead. A single core sustains ~8,900 TLS-proxied req/s. That puts it in line with the major reverse proxies for any realistic self-hosted load, the proxy is essentially never the bottleneck. Reproduce with `go test -bench=. ./internal/engine`; full methodology and numbers in [BENCHMARKS.md](BENCHMARKS.md).

## Documentation

Guides live in [`web/docs/`](web/docs/) and are **built into the web UI** — open Help (the `?` in the top bar) and pick a guide; they work fully offline, air-gapped installs included.

- [Getting started](web/docs/getting-started.md) — run it, first host, TLS modes, host types
- [Configuration reference](web/docs/configuration.md) — every env var and setting, real client IP, GeoIP, HTTP/3, IPv6
- [Access control & SSO](web/docs/sso.md) — access lists, **built-in OIDC login**, forward auth, per-path rules
- [Docker labels](web/docs/docker.md) — hosts and streams from container labels, multi-host
- [Streams & port forwards](web/docs/streams.md) — TCP/UDP forwarding, PROXY protocol, SNI routing, UPnP

## API

Everything the UI does is a REST call. Interactive Swagger UI at `/docs.html`, OpenAPI spec at `/openapi.yaml`, prose reference in [API.md](API.md). Create a bearer token in Profile > API tokens:

```bash
curl -H "Authorization: Bearer $TOKEN" http://<host>:81/api/hosts
```

Declarative bulk import (idempotent) via `POST /api/import` makes migrations scriptable — that is how the NPM/Pangolin migration of my own homelab was done.

## Building from source

```bash
go build .                   # single static binary
docker build -t quicgate .   # multi-stage, FROM scratch
```

Dev mode without TLS: `QG_TLS=off QG_HTTP=:8090 QG_ADMIN=:8091 QG_DATA=./devdata go run .`

## Design documents

- [SPEC.md](SPEC.md) — the NPM v2.12 feature-parity matrix and architecture decisions
- [ROADMAP.md](ROADMAP.md) — features mined from NPM's issue tracker (all five phases implemented)
- [API.md](API.md) — REST API reference

## Contributing

Issues and PRs welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) first (quicgate is deliberately opinionated: one binary, typed options, no free-text config).

## Security

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md). Do not open a public issue for security problems.

## License

[MIT](LICENSE)
