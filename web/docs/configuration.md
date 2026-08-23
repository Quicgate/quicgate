# Configuration reference

Process-level configuration is environment variables; everything else is edited live in the admin UI and stored in the database. Config changes hot-reload — there is no restart or reload command.

## Environment variables

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
| `QG_DOCKER_LABEL_PREFIX` | `quicgate` | label namespace to read (`<prefix>.enable`, `<prefix>.host`, ...) |

## Live settings

The Settings page edits these without a restart: ACME email / staging / custom CA URL, DNS-01 provider credentials (wildcards), certificate alert webhook (ntfy/Gotify style), default site (what unmatched domains get), auto-ban thresholds, admin OIDC/LDAP login, trusted proxies, and the Docker default domain.

## Real client IP behind another proxy

When quicgate sits behind Cloudflare or another load balancer, set **trusted proxies** (CIDRs) and the **real IP header** under Settings. Only when the TCP peer is inside a trusted CIDR does quicgate rewrite the client address from the header (rightmost-untrusted walk, so clients cannot spoof it). Access lists, GeoIP, rate limits, auto-ban and logs then all see the true client.

## GeoIP

Drop a `GeoLite2-Country.mmdb` into `QG_DATA` to enable country rules in access lists. Settings → GeoIP shows whether the database is loaded, lets you re-check without a restart, and has a test-an-IP lookup. Both IPv4 and IPv6 clients resolve.

## HTTP/3 notes

The TLS listener serves h1/h2 on TCP 443 and h3 on UDP 443 from the same certificates. Browsers upgrade via `Alt-Svc` and cache that hint for 30 days; disabling h3 per host therefore sends `Alt-Svc: clear` to actively evict the cached hint. Remember to forward **UDP 443** on your router or firewall (or let `QG_UPNP=1` do it).

## IPv6

quicgate is dual-stack out of the box: listeners accept IPv6 clients, upstreams and stream targets can be IPv6 literals or AAAA hostnames, and access lists and trusted-proxy lists take IPv6 CIDRs (a bare address is treated as `/128`). Per-IP rate limiting, auto-ban and GeoIP handle IPv6 the same as IPv4. Whether IPv6 traffic reaches quicgate is a DNS (AAAA record) and router question, not a quicgate one.

## Prometheus, logs, backups

- `/metrics` on the admin port exposes global and per-host metrics; scrape it with a bearer token (Profile → API tokens).
- JSON access logs rotate in `QG_DATA`; the System page has a viewer, and each host's Logs button filters to that host.
- Settings → Backup produces one archive with the full configuration; restore replaces everything. Backups from older quicgate versions restore fine.
