# quicgate roadmap

Sourced 2026-07-23 from the Nginx Proxy Manager issue tracker (reaction counts verified via the GitHub API). Each item: what, evidence, value for a homelab-focused NPM successor.

## STATUS: fully implemented (2026-07-23)

Every item below is now built and deployed (stack 350 on docker01), across five phases:
- **Phase 1** — dark/light theme (U1), host search (U2), noindex (S9), ACME staging (C9).
- **Phase 2** — backup/restore (A1), renewal visibility (C6), failure webhooks (A4), JSON access logs (L3).
- **Phase 3** — redirect/dead hosts (P4), default site (A5), rate limit (S8), block-exploits (S7), gzip, DNS-01 wildcards (C2), custom cert upload (C3), custom locations via path rewrite groundwork (P3).
- **Phase 4** — load balancing + health checks (P1/P2), static hosting (P6), forward-auth (S2), mTLS (C8), dynamic-DNS + GeoIP access rules (S6/S5), auto-ban (S1), 2FA (S4), API tokens (A3), log viewer (L1), Prometheus metrics (L2), self-signed/from-file/custom-CA certs (C1/C4/C5), effective-config viewer (U3), declarative import (A2), OIDC + LDAP admin login (S3/S10).
- **Phase 5** — PROXY protocol send+accept (T5), TLS termination (T3), SNI routing + passthrough (T2/C7), port ranges (T4), websocket support confirmed (P9).

Post-completion audit (2026-07-23) found and fixed one genuine miss and several skipped sub-parts:
- **P3** (custom locations + path rewrite) was marked done but never built — now implemented and verified.
- **A3** documentation half was missing — added [API.md](API.md) + OpenAPI/Swagger (`/docs.html`, `/openapi.yaml`).
- Filled skipped extras: **S7** bad-bot/scraper blocking, **P5** per-host custom 502 page, **L1** per-host log filter, **L2** per-host Prometheus counters.

Genuinely deferred (small, low-value, or optional): **C6** next-attempt renewal time (certmagic manages retries internally, not cleanly surfaceable), **S7** Coraza WAF (flagged optional in the roadmap itself).

Needs live infra to fully validate (wired + compile-verified, degrade safely): GeoIP (needs a MaxMind DB), OIDC/LDAP (need an IdP/directory), DNS-01 wildcards (needs the TransIP key), and real ACME issuance / public HTTP-3 (needs a public DNS + port-forward). Everything else was smoke-tested end to end.

---

Legend below (historical): `[HAVE]` = shipped before this roadmap, `[SPEC]` = was in SPEC.md milestones. All are now done.

## The headline: be "the reliable one"

NPM's chronic complaints are reliability, not features: cert renewal silently breaking (#2881, ~33 reactions on a *workaround* thread), DB vs rendered-config drift (#5690, #3497), upgrades breaking installs (#4606, #2753, #3473). quicgate's atomic in-memory config apply already kills the drift class. Lean into it: one-click backup, visible renewal state, failure notifications.

Top 5 unmet demands by reactions: mail/stream client-IP preservation (#1110, 169), UI backup/restore (#168, 158), dark mode (#707, 136), fail2ban-style banning (#39, 124), 2FA (#313, 109).

## Certificates / TLS

| # | Item | Evidence | Value |
|---|------|----------|-------|
| C1 | Self-signed / internal-CA certs from the UI (for `.lan` hosts ACME can't reach) | #593 (~45), #1884 | high |
| C2 | DNS-01 challenge + wildcards (libdns, TransIP first) `[SPEC]` | #378, #3753, #1106 | high |
| C3 | Custom cert upload, replaceable in place without relinking hosts `[SPEC]` | #87 (~40), #1618 (~32), #1911 | high |
| C4 | Cert from local file path (renewed externally) | #87, #1911 | medium |
| C5 | Custom ACME CA / directory URL (ZeroSSL, step-ca) | #1417 (~26) | medium-high |
| C6 | Visible renewal state + exact errors + next-attempt time in UI | #2881 (~33), #3575, #3250 | high |
| C7 | SSL passthrough (SNI-based, no termination) | #853 (~13) | medium |
| C8 | Client certificate auth (mTLS) per host | #768 (~53), #69 (~29) | high |
| C9 | Let's Encrypt staging toggle per cert (avoid rate-limit lockouts; env exists, make it per-cert) | #498, #1137 | medium |

## Security / Auth

| # | Item | Evidence | Value |
|---|------|----------|-------|
| S1 | Ban-tool integration: structured logs w/ real client IP + ban-list ingest API, or built-in auto-ban after N auth failures | #39 (~124), #734, #1131, #4475 | high |
| S2 | Forward-auth middleware (Authelia/Authentik/Keycloak per host, Traefik-style) | #437 (~37), #69 | high |
| S3 | OIDC login for the admin UI | #1624 (~40), #5126 (~31) | medium-high |
| S4 | 2FA/TOTP for admin login | #313 (~109), #4276 | high |
| S5 | GeoIP allow/deny in access lists (MaxMind/DB-IP) | #46 (~51), #595, #3334 | high |
| S6 | Dynamic-DNS hostnames in access lists (re-resolved periodically); trivial in Go, impossible in nginx | #1708 (~24) | high |
| S7 | WAF: block-common-exploits `[SPEC]`, bot/UA rules, optional Coraza (pure-Go ModSecurity) | #847 (~30), #4682 (~37), #5368 | medium-high |
| S8 | Rate limiting per host `[SPEC]` | #116 (~56) | high |
| S9 | "Block indexing" toggle (X-Robots-Tag: noindex) | #245 (~35) | medium, one-liner |
| S10 | LDAP/AD auth (OIDC covers most homelab cases) | #159 (~102), #4485 | low-medium |

## Streams

| # | Item | Evidence | Value |
|---|------|----------|-------|
| T1 | Per-stream source whitelist `[HAVE]` (allowedCidrs, 2026-07-23) | | |
| T2 | SNI-based routing for TLS streams (many services share 443 w/o termination) | #4119 (~20), #4070 | medium-high |
| T3 | TLS termination on streams (attach cert, forward plaintext) | #1829 (~33) | medium |
| T4 | Port ranges (28000-28999 in one rule) | #1969 (~21), #4720 | medium |
| T5 | PROXY protocol send + accept (real client IP to mail/game backends) | #1114 (~18) + label | medium-high |
| T6 | Mail proxying: deliver as streams + PROXY protocol (T5), not a mail-aware proxy | #1110 (~169) | medium |

## Proxy features

| # | Item | Evidence | Value |
|---|------|----------|-------|
| P1 | Load balancing: multiple upstreams, round-robin/ip-hash, failover | #156 (~69), #1963, #5322 | high |
| P2 | Backend health checks + up/down badge per host | #1726, #4352 | medium-high |
| P3 | Custom locations with path rewrite (strip/replace prefix); NPM's break hosts | #3512 (~32), #40 `[SPEC]` | high |
| P4 | Redirection hosts `[SPEC]` (NPM's are broken for many) | #4080 (~24), #525 | medium |
| P5 | Custom error pages / branded 502 `[SPEC]` | #26 (~55) | medium-high |
| P6 | Static site hosting (serve a local dir per host) | #58 (~40) | medium |
| P7 | HTTP/3 + QUIC `[HAVE]`; top-5 NPM ask, lead with it | #1550 (~94) | |
| P8 | Typed timeouts `[HAVE]` | #257 (~31) | |
| P9 | Websocket long-connection care (no write-timeout kills) + docs | #257 context | medium |

## Logging / Observability

| # | Item | Evidence | Value |
|---|------|----------|-------|
| L1 | Live access-log viewer in the UI (tail + filter per host) | #401 (~27), #724 | high |
| L2 | Traffic stats per host (requests, bandwidth, status codes) + Prometheus `[SPEC]` | #2395, #561 | medium-high |
| L3 | Structured JSON access logs, real client IP, rotation/retention; prereq for S1 | #183, #4594 | high |

## UI / UX

| # | Item | Evidence | Value |
|---|------|----------|-------|
| U1 | Dark mode (huisstijl tokens already support it: data-theme="light" flip) | #707 (~136), #3538 | high, cheap |
| U2 | Host search box; later tags/grouping | #409 (~27) | high (search) |
| U3 | Effective-config viewer ("applied = stored" proof); drift is impossible by design, show it | #5690, #3497 | medium |

## API / Automation / Ops

| # | Item | Evidence | Value |
|---|------|----------|-------|
| A1 | One-click backup/restore in UI (SQLite snapshot + cert dir), #2 most-reacted issue | #168 (~158) | high |
| A2 | Declarative import (YAML/JSON, GitOps-ish) | #2695, #4373 (~31) | medium-high |
| A3 | Documented REST API + long-lived scoped API tokens | #4852 | medium-high |
| A4 | Cert-renewal failure notifications (ntfy/Gotify/webhook/email) | #2881, #396 | high |
| A5 | Default-site for unmatched hosts incl. a cert so HTTPS misses aren't browser errors `[SPEC]` | #422 (~24) | medium |
| A6 | HA/clustering: non-goal; document cold-standby restore via A1 | #2330, #3651 | low |

## Non-goals

- Free-text nginx config box: the typed-options thesis IS the answer.
- FTP proxying (#568): out of scope.
- Multi-tenant per-user subdomains (#534): enterprise; planned multi-user + audit covers the homelab ask.

## Suggested order (homelab value per effort)

1. Cheap loud wins: dark mode (U1), noindex toggle (S9), staging toggle (C9), host search (U2).
2. Reliability story: backup/restore (A1), renewal state in UI (C6), renewal notifications (A4), JSON logs (L3).
3. M2 remainder from SPEC: custom locations w/ rewrite (P3), redirect/404 hosts, default site (A5), rate limit (S8), block-exploits, DNS-01 wildcards (C2), custom certs (C3), error pages (P5), compression.
4. Differentiators: forward-auth (S2), mTLS (C8), dynamic-DNS access lists (S6), GeoIP (S5), 2FA (S4), load balancing (P1) + health checks (P2).
5. Streams round 2: PROXY protocol (T5), SNI routing (T2), TLS termination (T3), port ranges (T4).
