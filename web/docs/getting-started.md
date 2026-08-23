# Getting started

quicgate is a single binary: proxy engine, ACME client, TCP/UDP streams, admin UI and REST API in one process, backed by one SQLite file.

## Run it

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

Open `http://<host>:81` and sign in with `admin@example.com` / `changeme` — a password change is forced on first login.

**Do not expose port 81 to the internet.** Proxy the admin UI through quicgate itself behind an access list, a VPN, or a firewall rule, like any other private service. Enable 2FA under Profile.

## Your first proxy host

Add a host on the Proxy Hosts page: one or more domains, an upstream `scheme://host:port`, and TLS mode **auto**. As soon as the domain resolves to your quicgate machine and ports 80/443 are reachable, the certificate issues automatically and the host serves over HTTP/1.1, HTTP/2 and HTTP/3.

Domain entries in the hosts table are clickable and open the site in a new tab.

## TLS modes

- **auto** — Let's Encrypt via HTTP-01. Wildcard domains (`*.example.com`) need DNS-01: configure a DNS provider under Settings.
- **custom** — upload your own certificate (Certificates page), or generate a self-signed one there.
- **http only** — no TLS for this host.

Force-SSL redirects HTTP to HTTPS per host; HSTS (with subdomains/preload) is a per-host toggle. A custom ACME CA (ZeroSSL, step-ca, ...) and the staging CA can be set under Settings.

## Host types

- **Proxy** — reverse proxy to an upstream, with a load-balancing pool, health checks, sticky sessions, custom locations and path rewrites.
- **Redirection** — 301/302/307/308 to another host, optionally preserving the path.
- **404 host** — claims a domain and serves a 404 (with a certificate, so the browser error is clean).
- **Static** — serves files from a directory in the container.

## Appearance

Two controls sit in the top bar. The **theme picker** chooses the skin:

- **Console** — the default: near-black surfaces, a single lime accent, Geist.
- **Brass & Iron** — warm metallics instead of cold neon: brass, copper and aged iron, with a Victorian display serif (Playfair Display), a readable body serif (Lora) and a mechanical mono (JetBrains Mono). Cards gain a thin brass edge along the top.

The **◐ button** switches light and dark *within* the chosen skin, so there are four combinations. Both choices persist in the browser and are applied before the first paint, so reloading never flashes the wrong palette.

Every typeface is vendored into the binary. Nothing is fetched from a font CDN, which keeps the admin origin's strict CSP intact and the whole UI working offline.

## Where things live

Everything is stored in `QG_DATA` (default `/data`): `quicgate.db` (all config), `certs/` (certmagic storage), and JSON access logs. One-click backup/restore lives under Settings; the backup contains hosts, access lists, identity providers, streams, settings, users and certificates.

## Next steps

- [Configuration reference](configuration.md) — every environment variable and setting.
- [Access control & SSO](sso.md) — access lists, built-in OIDC login, forward auth, per-path rules.
- [Docker labels](docker.md) — derive hosts from container labels.
- [Streams & port forwards](streams.md) — L4 forwarding, PROXY protocol, SNI routing, UPnP.
