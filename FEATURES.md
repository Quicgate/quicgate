# Feature status

Status as of **v1.9.1**. Every claim in the README and the guides should map to a row here. The
columns mean:

- **Tested locally**: covered by the automated test suite (unit and integration tests, real
  sockets and TLS where it matters, synthetic identity providers).
- **Qualified live**: exercised against real infrastructure in a production homelab deployment
  (real clients on the internet, real certificates, a real router).
- Anything not qualified live is built and tested, but has not been proven against every
  real-world environment it might meet (a specific IdP, DNS provider or load balancer).

## Proxying and TLS

| Feature | Tested locally | Qualified live | Notes |
|---|---|---|---|
| Reverse proxy, HTTP/1.1 and HTTP/2 | yes | yes | |
| HTTP/3 (QUIC) | yes | yes | UDP 443 must reach the host. The per-host switch controls `Alt-Svc` advertisement only; an explicit HTTP/3 request is still answered. |
| Automatic certificates, HTTP-01 | partly (no ACME server in tests) | yes | |
| DNS-01 wildcards (TransIP) | no | no | Needs a TransIP key to qualify. |
| Custom, self-signed and from-file certificates | yes | no | A replaced or restored certificate is served on the next reload. From-file certificates are read once, at import; later changes to the files are not picked up. |
| Client certificates (mTLS) | yes, real TLS, HTTP/2 reuse and HTTP/3 | no | Bound to the requested host on every request (421 on SNI/Host mismatch). |
| HSTS, security headers, header rules | yes | yes | |
| Load balancing, health checks, sticky sessions | yes | partly (health checks) | Health checks treat any HTTP response as alive. |
| Custom locations | yes | no | A location overrides its upstream and path rewrite only; other options are host-wide. |
| Response cache | yes | no | Only anonymous responses: bypassed for cookies, credentials, client certificates and authenticated requests. |
| Compression, maintenance mode, redirect, dead and static hosts | yes | partly | |
| IPv6 (clients, upstreams, rules) | yes | yes | |

## Access control

| Feature | Tested locally | Qualified live | Notes |
|---|---|---|---|
| Access lists: CIDR rules, basic auth, satisfy any/all | yes | yes (CIDR) | |
| Hostname (dynamic DNS) rules | yes, including resolver failure | no | Last-known-good addresses for 24 h; never widens on failure. |
| GeoIP country rules | yes | database loading only | Country rules never widen access while the database is not loaded. |
| Method-scoped rules, CORS preflight pass-through | yes | no | Preflights skip credential checks, never address rules. |
| Built-in OIDC SSO for hosts, per-path providers and policies | yes, synthetic IdP | no | Qualify against your IdP (Keycloak, Entra ID, Authentik) before relying on it. |
| Forward authentication | yes | no | |
| Path authentication (per-URL overrides) | yes | no | A rule whose gate cannot be built closes its path. |
| Rate limiting, bad-bot and exploit filters | yes | partly (filters) | Run before authentication. The exploit filter is a coarse tripwire, not a WAF. |
| Auto-ban | yes | no | Ban notifications are sent in the background. |
| Trusted proxies and real client IP | yes | no | |

## Streams and ports

| Feature | Tested locally | Qualified live | Notes |
|---|---|---|---|
| TCP streams, port ranges | yes | yes (TCP) | |
| UDP streams | yes | no | At most 1024 client sessions per listener, 64 per source address. |
| Access lists on streams (L4 semantics) | yes | no | Method-scoped allows never open a connection; lists that need credentials admit none. Changing a stream closes the connections it admitted. |
| PROXY protocol send | yes | no | |
| PROXY protocol accept | yes | no | Requires trusted proxies; other peers are never parsed. |
| TLS termination on streams | yes | no | Custom certificates only; managed ACME certificates are not available to streams. |
| SNI passthrough routing | yes | no | |
| Listener status (running or failed) | yes | no | |
| UPnP router port mapping | no | yes | Only maps ports to the quicgate host itself (router restriction). |

## Administration and operations

| Feature | Tested locally | Qualified live | Notes |
|---|---|---|---|
| Admin UI and API, CSRF and CSP | yes | yes | |
| Single admin account, 2FA (TOTP) | yes | account only | 2FA changes require the current password. |
| Admin login through OIDC or LDAP | yes, synthetic IdP | no | PKCE, nonce and one-use sign-in for OIDC; LDAP requires `ldaps://`. Neither asks for the local TOTP code: require MFA at the IdP or directory. |
| Session revocation (password change, sign out others, SSO key rotation) | yes | no | |
| API tokens | yes | yes | Full administrator credentials: no scopes, no expiry. |
| Backup and restore | yes | no | Restores every table and the certificate tree as a unit, or changes nothing. Refuses files that are not quicgate backups or would leave no admin able to sign in. Archives are not encrypted. |
| Declarative import | yes | no | One transaction, idempotent by natural key; never silently removes protection. (The earlier, non-transactional import was used for a live migration.) |
| Prometheus metrics | yes | no | Needs an API token to scrape. Per-host labels are bounded by configuration. |
| JSON access logs and viewer | yes | yes | |
| Docker label discovery (multi-host) | yes | no | Dormant unless enabled. |
| Graceful shutdown on SIGTERM | yes, on Linux | yes (v1.9.0 to v1.9.1 upgrade) | Plain HTTP drains for up to 5 s while HTTPS keeps serving, then HTTPS, streams and UPnP mappings close and the access log is flushed. |
| Signed build provenance for published images | CI | yes (v1.9.0) | `gh attestation verify oci://ghcr.io/quicgate/quicgate:<tag> --owner Quicgate` |

## Deferred

Planned in earlier documents and not built. They stay open until they are built or explicitly
dropped:

- Multiple admin users with roles, and an audit log of configuration changes.
- Scoped and expiring API tokens.
- Application-level encryption of stored private keys and provider secrets (use disk encryption
  and treat backups as sensitive).
- Per-location overrides of options other than upstream and path rewrite.
- Watching from-file certificates for renewal on disk.
- Managed ACME certificates for TLS termination on streams.
- Refusing explicit HTTP/3 per host (the switch only stops advertising it).
- Application-aware health checks (expected status, body, thresholds).
- An optional full WAF, and the next ACME renewal attempt time in the UI.

## Not goals

Clustering and high availability, Kubernetes ingress, a plugin marketplace, and tunnelling to
networks quicgate cannot reach directly.
