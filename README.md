# quicgate

Single-binary reverse proxy manager. The workflow of Nginx Proxy Manager, but the engine is native Go: HTTP/1.1, HTTP/2 and HTTP/3 (QUIC via quic-go), automatic Let's Encrypt certificates (certmagic), and every "advanced" option as a typed, validated setting instead of a free-text nginx blob. Config changes apply instantly, no reloads.

See [SPEC.md](SPEC.md) for the full NPM feature parity matrix and milestones.

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

First login: `admin@example.com` / `changeme` (password change forced).

## Run (docker)

```
docker build -t quicgate .
docker run -d -p 80:80 -p 443:443/tcp -p 443:443/udp -p 81:81 -v quicgate-data:/data quicgate
```
