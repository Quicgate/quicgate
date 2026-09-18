# Feature status

Status as of **v1.17.0**. Every claim in the README and the guides should map to a row here. The
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
| Auto-ban | yes | no | Ban notifications are sent in the background. Never-ban list, optionally with the machine's own and the router's public address. |
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
| WireGuard sites (upstreams and streams reached through a WireGuard peer) | yes: two real WireGuard devices over loopback, a request proxied end to end, mutation checks on no-fallback, connection closing and ownership reset | no | Userspace (wireguard-go on gVisor netstack), unprivileged. IPv4 only. TCP and UDP. Never a fallback to the local network. A dial-in site is called back at its last address after a restart (up to 40 s only if that address changed). Browser key generation needs HTTPS or localhost. |
| Hosts served on the VPN only, tunnel DNS | yes: a real WireGuard device over loopback; mutation checks on the public refusal (HTTP and TLS) and on the subject match | no | To everyone outside the tunnel the name does not exist. Certificates for such a name need DNS-01 or an upload. |
| VPN devices (added by an admin) | yes, including revocation, key reuse and address reuse | no | Keys made in the browser are verified against the embedded WireGuard implementation. The official iOS and Android apps have not been tested by the project. |
| VPN rules in access lists | yes | no | A request from outside the tunnel never matches a VPN rule; one from inside never matches an address or country rule. |
| VPN portal with single sign-on, authorization leases | yes: synthetic identity provider with refresh-token rotation; fresh-login check, refusal, outage and grace, hard limit, another subject, missing groups, the renewal-versus-admin race, blocking; mutation checks | no | Needs refresh tokens (`offline_access`), `auth_time` and `max_age` from the provider. Not yet qualified against a live Keycloak. |
| LAN access for people who logged in (**experimental**) | yes: forwarder end to end over real WireGuard devices, decision table, own-address and listener protection | no | Experimental until the code has had an outside review. Userspace proxying, not routing: the destination sees quicgate's address. TCP and UDP, IPv4, no ICMP. In Docker on a bridge network the host's addresses must be declared. Load and flood behaviour (spec S49) is limited by fixed budgets and not load-tested. |
| Break-glass VPN devices | yes | no | Password and TOTP to create, at most two, expiry unless waived. |

## Administration and operations

| Feature | Tested locally | Qualified live | Notes |
|---|---|---|---|
| Admin UI and API, CSRF and CSP | yes | yes | |
| Single admin account, 2FA (TOTP) | yes | account only | 2FA changes require the current password. |
| Admin login through OIDC or LDAP | yes, synthetic IdP | no | PKCE, nonce and one-use sign-in for OIDC; LDAP requires `ldaps://`. Neither asks for the local TOTP code: require MFA at the IdP or directory. |
| Session revocation (password change, sign out others, SSO key rotation) | yes | no | |
| API tokens | yes | yes | Full administrator credentials: no scopes, no expiry. |
| Backup and restore | yes | no | Restores every table and the certificate tree as a unit, or changes nothing. Refuses files that are not quicgate backups or would leave no admin able to sign in. Archives are not encrypted as a whole: secrets from the database are sealed inside them and the sealing key is never included, but the certificate tree (ACME and imported private keys) is in the clear. |
| Secrets encrypted at rest (2FA secrets, OIDC client secrets, DNS credentials, custom certificate keys, SSO cookie key) | yes, including a raw-byte search of the database, WAL and archive | no | XChaCha20-Poly1305, bound to row and column. A missing or wrong key locks the secrets and fails closed; it never replaces them. Rollback to an older version needs `quicgate -unseal`. |
| Declarative import | yes | no | One transaction, idempotent by natural key; never silently removes protection. (The earlier, non-transactional import was used for a live migration.) |
| Prometheus metrics | yes | no | Needs an API token to scrape. Per-host labels are bounded by configuration; per-listener, per-protocol and per-refusal-reason series are bounded too. |
| Traffic history and Overview charts | yes | yes (v1.11.1) | Sampled every 10 seconds, rolled up to 5 minutes and an hour, kept for a week in `traffic.json`. Bytes are counted on client sockets for HTTP, HTTPS and streams, and from QUIC's own counters for HTTP/3. Countries need a GeoIP database. |
| JSON access logs and viewer | yes | yes | |
| Docker label discovery (multi-host) | yes | no | Dormant unless enabled. |
| Graceful shutdown on SIGTERM | yes, on Linux | yes (v1.9.0 to v1.9.1 upgrade) | Plain HTTP drains for up to 5 s while HTTPS keeps serving, then HTTPS, streams and UPnP mappings close and the access log is flushed. |
| Signed build provenance for published images | CI | yes (v1.9.0) | `gh attestation verify oci://ghcr.io/quicgate/quicgate:<tag> --owner Quicgate` |

## Deferred

Planned in earlier documents and not built. They stay open until they are built or explicitly
dropped:

- Multiple admin users with roles, and an audit log of configuration changes.
- Scoped and expiring API tokens.
- Encryption of the ACME certificate files under `certs/` (database secrets are sealed; for the files use disk encryption
  and treat backups as sensitive).
- Per-location overrides of options other than upstream and path rewrite.
- Watching from-file certificates for renewal on disk.
- Managed ACME certificates for TLS termination on streams.
- Refusing explicit HTTP/3 per host (the switch only stops advertising it).
- Application-aware health checks (expected status, body, thresholds).
- An optional full WAF, and the next ACME renewal attempt time in the UI.

## Not goals

Clustering and high availability, Kubernetes ingress and a plugin marketplace. (Tunnelling to
networks quicgate cannot reach directly was on this list until 1.16, which added WireGuard
sites, and 1.17 added devices, the portal and LAN access; the design, its threat model and its
review record are in SPEC-wireguard.md.)
