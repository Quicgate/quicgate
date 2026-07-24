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
  <a href="https://github.com/maferick/quicgate/releases"><img src="https://img.shields.io/github/v/release/maferick/quicgate?color=a3e635&label=release" alt="latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-a3e635" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/go-1.26-00ADD8?logo=go" alt="Go 1.26">
  <img src="https://img.shields.io/badge/container-ghcr.io%2Fmaferick%2Fquicgate-0b0e0f" alt="ghcr.io/maferick/quicgate">
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
    image: ghcr.io/maferick/quicgate:latest
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

- **Hosts**: proxy, redirection (301/302/307/308), 404, and static-file hosts. Wildcard domains. Load-balanced upstream pools with active health checks. Custom locations (path prefix to a different upstream), path rewrites (strip/add prefix, RE2 regex).
- **TLS**: automatic Let's Encrypt (HTTP-01), DNS-01 wildcards, custom cert upload, self-signed generation, custom ACME CAs (ZeroSSL, step-ca), mTLS client certificates, per-host minimum TLS version, HSTS, hardened AEAD-only cipher defaults.
- **Security**: access lists (ordered CIDR / dynamic-DNS hostname / GeoIP-country rules + basic auth, satisfy any/all), forward-auth (Authelia / Authentik / Keycloak), per-IP rate limiting, block-common-exploits, bad-bot blocking, fail2ban-style auto-ban, search-engine noindex.
- **Streams (TCP/UDP)**: L4 port forwards with source whitelists, PROXY protocol v1/v2 (send and accept), TLS termination, SNI-based passthrough routing, port ranges. Plus pure router port-forwards managed over **UPnP IGD** (quicgate keeps your router's forwards in sync, self-healing after reboots).
- **Docker labels**: opt a container in with `quicgate.enable=true` and quicgate derives its host (and TCP/UDP streams) from labels automatically — Traefik's provider idea without the router/service/middleware label soup. Reuses named access lists, works with a host-networked quicgate, and every derived route is visible (with the reason it is or isn't routing) on the Docker page. See [Docker labels](#docker-labels-config-from-containers).
- **Ops**: JSON access logs with a built-in viewer (per-host and system-wide), Prometheus `/metrics` (global + per-host), one-click backup/restore, declarative JSON import, effective-config viewer, certificate renewal visibility with webhook alerts (ntfy/Gotify style).
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
| Identity-aware SSO on resources | forward-auth (Authelia etc.) | no | **built-in IdP/SSO** |
| Access lists (IP/CIDR) | yes + **GeoIP country + dynamic-DNS rules** | yes | yes |
| Auto-ban / abuse | built-in fail2ban-style + JSON logs for CrowdSec | no | CrowdSec integration |
| Router integration | **UPnP port-forward management** | no | no |
| Config from container labels | **yes — flat labels + streams, multi-host** | no | via Traefik labels |
| Admin 2FA | yes (TOTP) | no | yes |
| API | full REST + OpenAPI/Swagger + tokens | REST (undocumented) | REST |
| Metrics | Prometheus, per-host | no | via Traefik |
| Backup | one-click full backup/restore + JSON import | manual volume copy | manual |
| Maturity | **young, read the caveats** | battle-tested, huge community | growing fast |

**Choose NPM** if you want the most battle-tested option with years of community answers. **Choose Pangolin** if you need WireGuard tunnels to expose services on remote machines or built-in SSO in front of every resource. **Choose quicgate** if you want one small container that replaces the whole stack with a modern engine — this repo runs my entire homelab ingress (~50 hosts) as its production deployment.

### Honest caveats

- Young project with one production deployment (mine), so expect rough edges. Issues welcome.
- No WireGuard tunneling — quicgate proxies to network-reachable upstreams only.
- Single admin user (with 2FA/OIDC/LDAP), no multi-tenant roles.

## HTTP/3 notes

The TLS listener serves h1/h2 on TCP 443 and h3 on UDP 443 from the same certificates. Browsers upgrade via `Alt-Svc` and cache that hint for 30 days; disabling h3 per host therefore sends `Alt-Svc: clear` to actively evict the cached hint. Remember to forward **UDP 443** on your router or firewall (or let `QG_UPNP=1` do it).

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `QG_DATA` | `./data` | SQLite db + certmagic storage + logs |
| `QG_HTTP` | `:80` | plain HTTP listener (ACME + redirects) |
| `QG_HTTPS` | `:443` | TLS listener, TCP and UDP (HTTP/3) |
| `QG_ADMIN` | `:81` | management UI/API |
| `QG_ACME_EMAIL` | | ACME account email |
| `QG_ACME_STAGING` | | `1` = Let's Encrypt staging CA |
| `QG_TLS` | | `off` = dev run without TLS/QUIC listeners |
| `QG_H3` | | `off` = disable the HTTP/3 listener globally |
| `QG_UPNP` | | `1` = manage router port forwards via UPnP IGD |
| `QG_DOCKER` | | `1` = derive hosts/streams from container labels |
| `QG_DOCKER_SOCKET` | `/var/run/docker.sock` | local Docker daemon socket (mount read-only) |
| `QG_DOCKER_HOST_ADDR` | `127.0.0.1` | address where the local host's published ports are reachable |
| `QG_DOCKER_ENDPOINTS` | | JSON list of Docker hosts to watch (overrides the single local socket) |
| `QG_DOCKER_DOMAIN` | | default base domain for containers without `quicgate.host` |

Most settings (ACME email/staging/CA, DNS provider, alert webhook, default site, auto-ban, OIDC/LDAP, and the Docker default-domain) are editable live in the Settings page and stored in the database. Drop a `GeoLite2-Country.mmdb` into `QG_DATA` to enable GeoIP country rules in access lists.

## Docker labels (config from containers)

quicgate can read container labels and turn them into hosts and streams automatically — the Traefik provider idea, minus the router/service/middleware label soup. Opt a container in with `quicgate.enable=true` and it appears on the **Docker** page; usually two labels is all it takes. Nothing is persisted: derived routes re-derive from live containers on every change and at startup.

Enable the provider by mounting the daemon socket (read-only is enough — quicgate only ever lists, inspects, and watches events, it never writes) and setting `QG_DOCKER=1`:

```yaml
services:
  quicgate:
    image: ghcr.io/maferick/quicgate:1
    network_mode: host
    environment:
      QG_DOCKER: "1"
      QG_DOCKER_DOMAIN: apps.example.com    # optional: default base domain
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - quicgate-data:/data

  grafana:
    image: grafana/grafana
    ports: ["3000:3000"]
    labels:
      quicgate.enable: "true"
      quicgate.host: metrics.example.com    # or omit this, with QG_DOCKER_DOMAIN set
```

### Labels

| Label | Meaning | Default |
|---|---|---|
| `quicgate.enable` | opt this container in (**required**) | off |
| `quicgate.host` | public hostname(s), comma-separated | `<name>.<default-domain>` if one is set |
| `quicgate.port` | the app's port **inside the container** | auto if exactly one candidate |
| `quicgate.exclude-ports` | ports to ignore when auto-detecting | none |
| `quicgate.scheme` | upstream scheme `http` / `https` | `http` |
| `quicgate.tls-skip-verify` | trust a self-signed upstream | `false` |
| `quicgate.tls` | obtain a Let's Encrypt cert (public side) | `on` |
| `quicgate.access-list` | attach an existing access list by name | none |
| `quicgate.streams` | raw L4 forwards, comma-separated `[listen:]container[/proto]` | none |

`quicgate.streams` exposes non-HTTP ports as TCP/UDP streams, e.g. `quicgate.streams=25565, 2222:22/tcp, 53/udp` (proto `tcp`/`udp`/`both`, default `tcp`; `listen:` remaps the public port). Stream ports are automatically excluded from HTTP port auto-detection, so a container with a web port and a game port needs no `exclude-ports`. A container can be HTTP-only, streams-only (no hostname needed), or both.

Manual hosts always win a naming conflict — a label can never silently override a host you configured by hand. Anything beyond these labels (custom locations, header rules, mTLS, rate limits) lives in the UI: use **Convert to host** on the Docker page to turn a derived container into editable configuration with no downtime.

### How quicgate reaches containers

One rule: quicgate connects to the **Docker host's address** on the container's **published port**. `quicgate.port` names the app's port *inside* the container; quicgate uses that port's published host mapping (a `network_mode: host` container is reached at that port directly). So a container must publish the port you want routed. The local host's address defaults to `127.0.0.1` (`QG_DOCKER_HOST_ADDR`).

### Multiple Docker hosts

quicgate can watch several daemons at once. Give it a JSON list of endpoints (in `QG_DOCKER_ENDPOINTS`, or the **Docker hosts** box on the Docker page), each with a name, a connection, and the address where *its* published ports are reachable from quicgate:

```json
[
  {"name": "local",    "connect": "/var/run/docker.sock",    "address": "127.0.0.1"},
  {"name": "docker92", "connect": "tcp://192.168.1.92:2375", "address": "192.168.1.92"}
]
```

A container on `docker92` is then reached at `192.168.1.92:<published port>`. Reach a remote daemon through a **read-only socket proxy** (below) exposing `tcp://` on the LAN. Endpoint-list changes apply on restart; the Docker page shows each host's connection state.

### Socket security

The provider is read-only, but the socket still grants broad access to the daemon. Mount it `:ro`, and for least privilege put a read-only socket proxy (e.g. `tecnativa/docker-socket-proxy` with only `CONTAINERS=1` and `EVENTS=1`) in front of it and point `QG_DOCKER_SOCKET` at the proxy.

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
