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

Drop a `GeoLite2-Country.mmdb` into `QG_DATA` to enable country rules in access lists. Settings → Client IP & GeoIP shows whether the database is loaded, lets you re-check without a restart, and has a test-an-IP lookup. Both IPv4 and IPv6 clients resolve.

## HTTP/3 notes

The TLS listener serves h1/h2 on TCP 443 and h3 on UDP 443 from the same certificates. Browsers upgrade via `Alt-Svc` and cache that hint for 30 days; disabling h3 per host therefore sends `Alt-Svc: clear` to actively evict the cached hint. The per-host switch controls advertisement only: a client that already speaks HTTP/3 to the listener is still answered. Remember to forward **UDP 443** on your router or firewall (or let `QG_UPNP=1` do it).

## IPv6

quicgate is dual-stack out of the box: listeners accept IPv6 clients, upstreams and stream targets can be IPv6 literals or AAAA hostnames, and access lists and trusted-proxy lists take IPv6 CIDRs (a bare address is treated as `/128`). Per-IP rate limiting, auto-ban and GeoIP handle IPv6 the same as IPv4. Whether IPv6 traffic reaches quicgate is a DNS (AAAA record) and router question, not a quicgate one.

## Prometheus, logs, backups

- `/metrics` on the admin port exposes global and per-host metrics; scrape it with a bearer token (account menu → API tokens). Per-host series are labelled by configured route (`app.example.com`, `*.example.com`), and all traffic for names no host serves shares the `_unmatched` label, so invented Host headers cannot grow the metrics. Per-listener series count the bytes and connections on each port quicgate listens on (`tcp:443`, `udp:443` for HTTP/3, a stream's first port), and `quicgate_blocked_total{reason}` counts what quicgate refused.
- The Overview charts come from a traffic history the engine keeps itself: a sample every 10 seconds for the last hour, 5-minute totals for the last day and hourly totals for the last week. It is saved to `traffic.json` in `QG_DATA` every 5 minutes and at shutdown, so a restart or upgrade keeps it; it is not part of backups, and deleting the file only clears the charts. Bytes are measured on the client side of every listener, TLS and protocol overhead included. The countries panel needs the GeoIP database; private addresses count as the local network.
- Auto-ban keeps its bans in `bans.json` in `QG_DATA`, written whenever a ban starts or is lifted and at shutdown, so a restart or upgrade does not lift them; bans that expired meanwhile are dropped at startup. Access control lists the banned addresses with the reason and host, and can lift a ban.
- JSON access logs rotate in `QG_DATA`; the Logs page has a viewer for traffic that matched no host, all traffic or a single host, and each host's Logs button opens it for that host.
- Settings → Backup & restore produces one archive with the full configuration: every database table (including API tokens and router port forwards) plus the certificate storage. The archive is built completely before it is sent, so a file that cannot be read fails the export instead of producing a truncated archive.
- Restore replaces everything as one unit. Every table is replaced, tables an older backup lacks are emptied (a restore never leaves live rows such as API tokens mixed in), and columns are matched by name so backups from older quicgate versions restore with defaults for newer fields. The certificate tree is swapped in whole; if anything fails, the previous certificates are put back, the database is untouched, and the error says so. After a restore every admin session ends; sign in with the restored credentials. A backup whose hosts or streams reference objects that do not exist restores with warnings, and those parts fail closed. A file that is not a quicgate backup, or a backup that would leave no admin account able to sign in, is refused and nothing changes.
- Settings → Backup & restore → Import applies a JSON document of `accessLists`, `hosts` and `streams` in one transaction: a document with any invalid entry changes nothing. Entries that match existing configuration (access lists by name, hosts by their set of domains, streams by listen port and protocol) are updated in place, so importing the same document again is harmless. An access list's `id` in the document is the document's own: hosts, path rules and streams that reference it are bound to that list, whatever id the database gives it. Other references (`accessListId` of a list the document does not define, `certId`, a provider id) name existing objects and must resolve. An update never silently removes protection: a document that would drop a host's access list, SSO, forward auth, client certificates or a gated path, a stream's source restriction, or every rule and user of an access list is refused; change those in the UI or API.
