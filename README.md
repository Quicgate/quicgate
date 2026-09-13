<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/logo-full-dark.svg">
    <img src="brand/logo-full.svg" alt="quicgate" height="84">
  </picture>
</p>

<p align="center">
  <b>A self-hosted reverse proxy manager with single sign-on built in — one Go binary.</b><br>
  Point-and-click like Nginx Proxy Manager &middot; identity-aware like Pomerium &middot; HTTP/3 &middot; no nginx, no Traefik, no sidecars.
</p>

<p align="center">
  <a href="https://github.com/Quicgate/quicgate/releases"><img src="https://img.shields.io/github/v/release/Quicgate/quicgate?color=a3e635&label=release" alt="latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-a3e635" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/go-1.26-00ADD8?logo=go" alt="Go 1.26">
  <img src="https://img.shields.io/badge/container-ghcr.io%2Fquicgate%2Fquicgate-0b0e0f" alt="ghcr.io/quicgate/quicgate">
  <img src="https://img.shields.io/badge/image%20size-~25MB-a3e635" alt="image size">
</p>

---

**quicgate** is a reverse proxy manager for self-hosters and homelabs: a web UI for HTTPS proxy hosts,
automatic Let's Encrypt certificates, TCP/UDP streams, access lists — and **OpenID Connect SSO in
front of any host**, run by quicgate itself against Keycloak, Entra ID, Authentik or any
spec-compliant identity provider.

It replaces this stack with one container:

| Instead of | quicgate gives you |
|---|---|
| Nginx Proxy Manager / nginx | proxy hosts, certificates, redirects, static sites, a UI |
| Traefik / Caddy | routing, ACME, Docker label discovery, HTTP/3 |
| Authelia / oauth2-proxy / Pomerium | identity-aware access: OIDC login, group policy, `Remote-User` upstream |
| fail2ban, a metrics exporter, a log viewer | auto-ban, Prometheus `/metrics`, JSON access logs |

> It exists because I loved Nginx Proxy Manager's workflow but not its internals, and loved
> Pangolin's engine but not its complexity. So: the NPM experience, rebuilt on a modern native-Go
> data plane, in a single `FROM scratch` container.

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

Open `http://<host>:81`, sign in with `admin@example.com` / `changeme` (a password change is forced),
add your first proxy host, and the certificate issues automatically.

> **Never expose port 81 to the internet.** Put the admin UI behind quicgate itself with an access
> list, a VPN, or a firewall rule — like any other private service.

## Single sign-on, without a sidecar

Most proxies hand SSO to a second service. quicgate runs the OpenID Connect login itself: PKCE and a
nonce, ID-token signature verification, and a signed session cookie bound to the host **and** to the
provider that issued it.

Define an identity provider once, then per host choose who gets in — by email, by email domain or by
group — and optionally pass the identity upstream as `Remote-User` / `Remote-Email` / `Remote-Groups`,
so apps with proxy-auth support log the user straight in. Inbound copies of those headers are always
stripped, so a client can never forge them.

Authentication can differ **per URL** on the same host, which is what real apps need:

| Path | Gate |
|---|---|
| `/ValidationService.asmx` | public — a licensing callback that cannot log in |
| `/webhooks/` | public, `POST` only |
| `/admin/` | OIDC, group `platform-admins` |
| everything else | OIDC, any employee |

Different paths can even use **different identity providers** — staff on the company IdP, a partner
endpoint on theirs. Already running Authelia or Authentik? Point a host at its verify endpoint with
forward-auth instead. Detail in the [Access control & SSO guide](web/docs/sso.md).

## Highlights

**Proxying** — proxy, redirect (301/302/307/308), 404 and static hosts · wildcard domains ·
load-balanced pools with health checks and sticky sessions · custom locations · path rewrites
(strip/add prefix, RE2) · maintenance mode · response caching · gzip

**TLS & HTTP/3** — automatic Let's Encrypt (HTTP-01), DNS-01 wildcards, custom ACME CAs (ZeroSSL,
step-ca) · upload your own certificates or generate self-signed · mTLS client certificates · HSTS ·
h1/h2/**h3 (QUIC)** on every host, with a per-host toggle

**Access control** — ordered access lists by IP/CIDR, dynamic-DNS hostname or GeoIP country ·
basic auth · per-rule HTTP-method scoping · built-in OIDC SSO and forward-auth · per-path rules ·
rate limiting · exploit and bad-bot filters · fail2ban-style auto-ban · real client IP behind
Cloudflare or another load balancer

**Streams (TCP/UDP)** — L4 forwards with source whitelists · PROXY protocol v1/v2 · TLS termination ·
SNI passthrough routing · port ranges · plus router port-forwards managed over **UPnP**, self-healing
after a reboot

**Docker** — opt a container in with `quicgate.enable=true` and its host (and streams) are derived
from labels: Traefik's provider idea without the router/service/middleware soup. Multi-host, and
every derived route shows why it is or is not routing

**Dual-stack** — IPv6 clients, IPv6-literal and AAAA upstreams, IPv6 CIDRs in access lists and
trusted-proxy lists, GeoIP and rate limits on v6 alike

**Ops** — Overview dashboard · JSON access logs with a built-in viewer · Prometheus `/metrics` ·
one-click backup/restore · declarative JSON import · certificate-renewal alerts (ntfy/Gotify) ·
TOTP 2FA · API tokens · OIDC/LDAP admin login · offline guides in the UI · light/dark and a choice of
themes

## How it compares

| | **quicgate** | **Nginx Proxy Manager** | **Pangolin** |
|---|---|---|---|
| Data plane | native Go (net/http, quic-go) | nginx | Traefik |
| Deployment | **1 container, ~25 MB, scratch** | 1 container (+optional db) | 3+ containers |
| HTTP/3 (QUIC) | **default, per-host toggle** | no | via Traefik config |
| Config model | **typed, validated options** | UI + free-text nginx snippets | UI + Traefik config |
| Reloads | instant atomic swap | nginx reload | Traefik provider push |
| SSO on your services | **built-in OIDC + forward-auth** | no | **built-in IdP/SSO** |
| Per-URL auth policy | **yes** | no | per-resource |
| Access lists | IP/CIDR + **GeoIP + dynamic DNS** | IP/CIDR | yes |
| TCP/UDP streams | yes + PROXY protocol + SNI + TLS termination | basic | via tunnels |
| WireGuard tunnels to remote sites | no | no | **yes — Pangolin's killer feature** |
| Config from container labels | **yes, flat labels + streams** | no | via Traefik labels |
| Metrics / API | Prometheus + full REST + OpenAPI | none / undocumented REST | via Traefik / REST |
| Maturity | **young — read the caveats** | battle-tested, huge community | growing fast |

**Choose NPM** for the most battle-tested option and years of community answers.
**Choose Pangolin** if you need WireGuard tunnels to reach services on remote machines.
**Choose quicgate** if you want one small container to replace the whole stack — proxy, certificates,
access control and SSO — on a modern engine.

### Honest caveats

- Young project with one production deployment (mine, ~50 hosts), so expect rough edges. Issues welcome.
- No WireGuard tunnelling — quicgate proxies to network-reachable upstreams only.
- Single admin user (with 2FA / OIDC / LDAP), no multi-tenant roles.

## Performance

On a Ryzen 7 9800X3D: **~45,000 proxied requests/sec** to a local backend, **~180,000/sec** for cache
hits, ~9 ns routing lookups, and ~8,900 TLS-proxied req/s on a single core. Access lists add no
measurable overhead. Those are microbenchmarks on one machine, not a sustained-load qualification, and
authentication, TLS and your backends change the picture, so measure your own workload. Reproduce
with `go test -bench=. ./internal/engine`; methodology in [BENCHMARKS.md](BENCHMARKS.md).

## Documentation

Guides live in [`web/docs/`](web/docs/) and are **built into the binary** — open Help (`?` in the top
bar) and pick one. They work offline, air-gapped installs included.

- [Getting started](web/docs/getting-started.md) — run it, first host, TLS modes, host types, themes
- [Configuration reference](web/docs/configuration.md) — env vars and settings, real client IP, GeoIP, HTTP/3, IPv6
- [Access control & SSO](web/docs/sso.md) — access lists, OIDC login, forward auth, per-path rules, security model
- [Docker labels](web/docs/docker.md) — hosts and streams from container labels, multi-host
- [Streams & port forwards](web/docs/streams.md) — TCP/UDP forwarding, PROXY protocol, SNI routing, UPnP

What is built, tested and qualified against real infrastructure, and what is deliberately deferred, is
tracked in [FEATURES.md](FEATURES.md).

## API

Everything the UI does is a REST call — interactive Swagger at `/docs.html`, spec at `/openapi.yaml`,
prose in [API.md](API.md). Create a bearer token under Profile → API tokens:

```bash
curl -H "Authorization: Bearer $TOKEN" http://<host>:81/api/hosts
```

`POST /api/import` does idempotent declarative bulk import, which is how my own NPM and Pangolin
migrations were scripted.

## Building from source

```bash
go build .                   # single static binary
docker build -t quicgate .   # multi-stage, FROM scratch
```

Dev mode without TLS: `QG_TLS=off QG_HTTP=:8090 QG_ADMIN=:8091 QG_DATA=./devdata go run .`

## Project

- [SPEC.md](SPEC.md) — the NPM feature-parity matrix and architecture decisions
- [ROADMAP.md](ROADMAP.md) — features mined from NPM's issue tracker (all five phases implemented)
- [CHANGELOG.md](CHANGELOG.md) — what changed, release by release
- [CONTRIBUTING.md](CONTRIBUTING.md) — quicgate is deliberately opinionated: one binary, typed options, no free-text config
- [SECURITY.md](SECURITY.md) — found a vulnerability? Report it privately, never as a public issue

## License

[MIT](LICENSE)
