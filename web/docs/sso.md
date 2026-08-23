# Access control & SSO

quicgate has three gates you can put in front of a proxy host, combinable and — since v1.7.0 — overridable per URL path.

## Access lists

An access list is an ordered set of rules plus optional basic-auth users, reusable across hosts and streams.

- **Rules**: allow/deny by IP/CIDR, by hostname (dynamic DNS, re-resolved periodically), or by GeoIP country. First match wins; no match denies. A rule can be scoped to specific HTTP verbs — e.g. allow `GET` from everywhere but gate `POST`/`PUT`.
- **Users**: bcrypt basic auth. **Satisfy any** = IP rule *or* login passes; **satisfy all** = both must pass.
- **Pass Authorization header**: off by default when the list has users (quicgate consumes the header for basic auth). A pure IP list never strips it, so bearer-token APIs behind an IP allowlist keep working.
- CORS preflights (`OPTIONS` with `Access-Control-Request-Method`) always pass the gate; the real request is still gated.

## Built-in OIDC SSO

quicgate can run the OpenID Connect login itself — no Authelia, oauth2-proxy or Pomerium needed.

1. **Add a provider** under Access Lists → Identity providers: name, issuer URL (the OIDC discovery base, e.g. `https://idp.example.com/realms/main`), client ID and secret. Optional: scopes (default `openid email profile`), the ID-token claim holding groups (default `groups`), session lifetime (default 12h), and skip-TLS-verify for IdPs on an internal CA.
2. **Register the redirect URI** at the IdP: `https://<host>/.qg/oidc/callback` for every protected host. Keycloak accepts wildcards (`https://*.example.com/.qg/oidc/callback`); Entra ID needs each host listed.
3. **Enable OIDC SSO on the host** (Security tab): pick the provider and set the policy — allowed emails, allowed domains, allowed groups. All three empty means any authenticated user. Any one match admits.

What happens at runtime: an anonymous request is redirected to the IdP (auth-code flow with PKCE and a nonce); after login quicgate verifies the ID token against the IdP's keys, applies your policy, and sets a signed session cookie. Sessions are stateless, survive restarts, and are bound to the exact host they were minted for — a session for one host can never be replayed against another. Sign out at `/.qg/oidc/logout`.

**Identity headers.** With *Pass identity upstream* enabled, the upstream receives `Remote-User`, `Remote-Email` and `Remote-Groups` — apps that support proxy auth log the user straight in. Inbound copies of these headers are always stripped on OIDC hosts (public paths included), so a client can never spoof them through quicgate. Make sure the upstream only accepts traffic from quicgate, or header trust is meaningless.

If the provider referenced by a host is deleted, the host fails closed (403) rather than turning public.

## Forward authentication

Prefer an existing Authelia / Authentik / Keycloak-gatekeeper setup? Point the host's **Forward authentication** at its verify endpoint. quicgate mirrors Traefik's forwardAuth: each request is checked against the endpoint, chosen response headers are copied upstream on success, and 401/redirect responses pass through to the client.

## Path authentication (per-URL overrides)

Security tab → **Path authentication** takes ordered rules of path + match (**prefix**/**exact**) + mode:

- **Public** — no auth for this path.
- **Access list** — a specific list, possibly different from the host's.
- **Forward auth** — the host's forward-auth endpoint.
- **OIDC SSO** — the host's OIDC login.

The longest matching path wins (exact beats prefix at equal length); a path matching no rule keeps the host's own gate. Rules can be scoped to HTTP verbs. Typical use: an SSO-gated app whose licensing callback, webhook receiver or health probe must answer without credentials:

| Path | Match | Mode |
|---|---|---|
| `/ValidationService.asmx` | exact | Public |
| `/manage/` | prefix | Public |
| `/admin/` | prefix | Access list: staff |
| *(everything else)* | | host's gate (e.g. OIDC) |

Rate limits, bad-bot and exploit filters stay host-wide — they are abuse controls, not auth, and public paths need them most.

## Evaluation order

Per request, outermost first: access list → forward auth → OIDC SSO → rate limit → bad bots → exploit filter → cache/compression → proxy. Path rules replace the first three for matching paths. Auto-ban records failures from access-list denials and repeated offenders are banned at the IP level.

## Security model

What quicgate guarantees, and what it expects from you.

**Path handling.** Any request whose path contains a `.` or `..` segment is rejected with 400 before it reaches a gate, a path rule or an upstream. Otherwise `/public/../admin` would match a public rule here while an upstream that resolves dot segments served `/admin` — a bypass of every gate on the host. Dot-prefixed names such as `/.well-known/acme-challenge/...` are unaffected: only whole `.`/`..` segments are refused.

**Identity headers cannot be spoofed.** On a host with OIDC SSO, `Remote-User`, `Remote-Email` and `Remote-Groups` are stripped from every inbound request, including public path carve-outs, before any gate runs. On a forward-auth host, whatever headers you list under *Copy response headers upstream* are stripped from the inbound request too, so a 2xx from the auth server that omits one cannot let the client's own value through.

**Still, restrict your backends.** Header-based identity is only as good as the network path. If an upstream is reachable directly, anyone who can reach it can set `Remote-User` themselves and quicgate never sees the request. Bind backends to the quicgate host, or firewall them to it.

**Sessions.** The SSO cookie is HMAC-signed with a per-install secret, `HttpOnly`, `SameSite=Lax`, and marked `Secure` whenever the client connection is HTTPS — including when TLS terminates on a proxy in front (`X-Forwarded-Proto`). It is bound to the exact host it was minted for, so a session for one host cannot be replayed against another that trusts different groups. Sessions are stateless: they cannot be revoked individually before they expire, so keep the lifetime modest for sensitive hosts. Rotating the provider or clearing `sso_cookie_secret` invalidates every session at once. Group membership is captured at login, so a group change takes effect at the next login (or when the session expires), while the host's allow-lists are re-evaluated on every request.

**Email verification.** A login is refused when the identity provider explicitly marks the address unverified (`email_verified: false`), so an IdP that lets users set their own address cannot be used to claim someone@your-domain and satisfy an allowed-domains rule. Providers that omit the claim are taken at their word.

**Empty policy means any authenticated user.** With no allowed emails, domains or groups, every account the IdP will authenticate gets in. That is fine for a private Keycloak realm and dangerous for a public IdP — set at least a domain or group rule when the provider is not exclusively yours.

**CORS preflights pass the gate.** An `OPTIONS` request carrying `Access-Control-Request-Method` reaches the upstream unauthenticated, by spec: preflights carry no credentials, and gating them breaks every cross-origin app. The real request that follows is gated normally, and identity headers are stripped from the preflight too.

**Admin API.** Failed logins are counted per client IP and the address is locked out after 10 failures in 15 minutes, covering the six-digit TOTP code as well as the password. The admin UI sets `SameSite=Strict` session cookies, applies a same-origin check to cookie-authenticated writes, and serves a strict CSP. Credentials for other systems (the IdP client secret, DNS provider keys) are never returned by the settings API — reads show a mask, and sending the mask back keeps the stored value.

**Never expose the admin port.** Port 81 behind an access list, VPN or firewall, always.
