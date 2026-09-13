# Access control & SSO

quicgate has three gates you can put in front of a proxy host, combinable and — since v1.7.0 — overridable per URL path.

## Access lists

An access list is an ordered set of rules plus optional basic-auth users, reusable across hosts and streams.

- **Rules**: allow/deny by IP/CIDR, by hostname (dynamic DNS, re-resolved periodically), or by GeoIP country. First match wins; no match denies. A rule can be scoped to specific HTTP verbs — e.g. allow `GET` from everywhere but gate `POST`/`PUT`.
- **Users**: bcrypt basic auth. **Satisfy any** = IP rule *or* login passes; **satisfy all** = both must pass.
- **Pass Authorization header**: off by default when the list has users (quicgate consumes the header for basic auth). A pure IP list never strips it, so bearer-token APIs behind an IP allowlist keep working.
- CORS preflights (`OPTIONS` with `Access-Control-Request-Method`) always pass the gate; the real request is still gated.
- **A failing rule never widens access.** If a hostname rule stops resolving, it keeps its last resolved addresses for up to 24 hours; after that (or with no earlier answer) an unresolved *allow* matches nobody and an unresolved *deny* denies everyone who reaches it. Country rules behave the same way while the GeoIP database is not loaded. Only a list with no IP, hostname or country rule at all is unrestricted by address. Affected routes show a warning in the effective-config view.
- **In-use lists cannot be deleted.** A list that a host, a path rule or a stream still uses is refused on delete; detach it first. A reference that is missing anyway (an old row, a restored backup) closes the host, path or stream instead of opening it.

## Built-in OIDC SSO

quicgate can run the OpenID Connect login itself — no Authelia, oauth2-proxy or Pomerium needed.

1. **Add a provider** under Access Lists → Identity providers: name, issuer URL (the OIDC discovery base, e.g. `https://idp.example.com/realms/main`), client ID and secret. Optional: scopes (default `openid email profile`), the ID-token claim holding groups (default `groups`), session lifetime (default 12h), and skip-TLS-verify for IdPs on an internal CA.
2. **Register the redirect URI** at the IdP: `https://<host>/.qg/oidc/callback` for every protected host. Keycloak accepts wildcards (`https://*.example.com/.qg/oidc/callback`); Entra ID needs each host listed.
3. **Enable OIDC SSO on the host** (Security tab): pick the provider and set the policy — allowed emails, allowed domains, allowed groups. All three empty means any authenticated user. Any one match admits.

**Groups need a mapper.** Keycloak does not put groups in the ID token by default: add a *group membership* mapper to the client (claim name `groups`, full path off) or every group rule silently matches nothing. Entra ID needs the equivalent groups claim configured on the app registration.

**Several providers on one host.** Define as many providers as you like and reference them per host, or per path via a path rule. Two entries may share an issuer with different client ids, which is the tidy way to give each host its own app registration, secret and mappers. Sessions are bound to the provider that issued them as well as to the host, so a login through one IdP never satisfies a path gated by another.

**The admin login can reuse a provider too.** Settings → OIDC login has an *Identity provider* picker listing the same providers; leave it on "use the fields below" to keep configuring the admin IdP inline. Give the control plane its own client on the IdP regardless: it deserves a separate audience from the applications behind it, and its own allow-list applies either way.

What happens at runtime: an anonymous request is redirected to the IdP (auth-code flow with PKCE and a nonce); after login quicgate verifies the ID token against the IdP's keys, applies your policy, and sets a signed session cookie. Sessions are stateless, survive restarts, and are bound to the exact host they were minted for — a session for one host can never be replayed against another. Sign out at `/.qg/oidc/logout`.

**Identity headers.** With *Pass identity upstream* enabled, the upstream receives `Remote-User`, `Remote-Email` and `Remote-Groups`, and apps that support proxy auth log the user straight in. Inbound copies of these headers are stripped on every host that has SSO on the host or on any path rule (public paths included), so a client can never spoof them through quicgate. Make sure the upstream only accepts traffic from quicgate, or header trust is meaningless.

A provider that a host, a path rule or the admin login still uses cannot be deleted. If a reference is missing anyway, the host fails closed (403) rather than turning public.

## Forward authentication

Prefer an existing Authelia / Authentik / Keycloak-gatekeeper setup? Point the host's **Forward authentication** at its verify endpoint. quicgate mirrors Traefik's forwardAuth: each request is checked against the endpoint, chosen response headers are copied upstream on success, and 401/redirect responses pass through to the client.

## Path authentication (per-URL overrides)

Security tab → **Path authentication** takes ordered rules of path + match (**prefix**/**exact**) + mode:

- **Public**: no auth for this path.
- **Access list**: a specific list, possibly different from the host's.
- **Forward auth**: the host's forward-auth endpoint.
- **OIDC SSO**: an OpenID Connect login. By default the host's provider; a rule can name a *different* provider (and its own allowed groups), so one host can send `/staff` to the company IdP and `/partner` to another, or use a separate app registration per URL on the same IdP. Every rule's policy is enforced on its own, even on the same provider as the host: a `/admin/` rule that admits only admins is never widened by a host policy that admits all employees, and the login is finished by the rule that started it.

A rule whose gate cannot be built refuses every request on its path: an access list that no longer exists, *Forward auth* on a host without a forward-auth endpoint, or *OIDC SSO* with no provider on the rule or the host. It never falls back to the host's gate, which may be public.

The longest matching path wins (exact beats prefix at equal length); a path matching no rule keeps the host's own gate. Rules can be scoped to HTTP verbs. Typical use: an SSO-gated app whose licensing callback, webhook receiver or health probe must answer without credentials:

| Path | Match | Mode |
|---|---|---|
| `/ValidationService.asmx` | exact | Public |
| `/manage/` | prefix | Public |
| `/admin/` | prefix | Access list: staff |
| *(everything else)* | | host's gate (e.g. OIDC) |

Rate limits, bad-bot and exploit filters stay host-wide — they are abuse controls, not auth, and public paths need them most.

## Evaluation order

Per request, outermost first: rate limit, bad bots, exploit filter, identity-header strip, then the gates (access list, forward auth, OIDC SSO), then cache/compression and the proxy. The abuse controls run before any gate, so a flood of credential guesses or login redirects is throttled before it costs a password comparison, a forward-auth call or an IdP round trip. Path rules replace the three gates for matching paths. Auto-ban records failures from access-list denials and repeated offenders are banned at the IP level.

## Security model

What quicgate guarantees, and what it expects from you.

**Path handling.** Any request whose path contains a `.` or `..` segment is rejected with 400 before it reaches a gate, a path rule or an upstream. Otherwise `/public/../admin` would match a public rule here while an upstream that resolves dot segments served `/admin` — a bypass of every gate on the host. Dot-prefixed names such as `/.well-known/acme-challenge/...` are unaffected: only whole `.`/`..` segments are refused.

**Identity headers cannot be spoofed.** On a host with OIDC SSO on the host or on any path rule, `Remote-User`, `Remote-Email` and `Remote-Groups` are stripped from every inbound request, including public path carve-outs, before any gate runs. On a forward-auth host, whatever headers you list under *Copy response headers upstream* are stripped from every inbound request as well, on every path, so neither a public carve-out nor a 2xx from the auth server that omits one can let the client's own value through.

**Client certificates (mTLS) are bound to the host.** A host with *Client certificate* set to *require* or *request* checks the certificate on every request, not only in the TLS handshake. A request whose TLS server name (SNI) selects a different host is answered `421 Misdirected Request` whenever either host takes client certificates, which also covers HTTP/2 and HTTP/3 connections reused for another name; clients retry on a fresh connection. The certificate is verified again against the host's current CA bundle, so replacing the bundle applies to connections that are already open. Such a host is HTTPS only: plain HTTP is redirected whatever its force-SSL setting. A CA bundle must contain at least one parsable certificate, and client certificates need a TLS host (not certMode *none*).

**The response cache only holds anonymous responses.** A host with *cache* enabled never answers from, or stores into, the shared cache for a request that carries a cookie, arrived with an `Authorization` header (even one an access list consumed), or was admitted by a basic-auth user, an SSO session or forward auth. Cached entries vary on the client's `Accept-Encoding`; responses with `Set-Cookie`, `private`, `no-store`, `no-cache`, `max-age=0` or a `Vary` other than `Accept-Encoding` are not stored, and a request `Cache-Control: no-cache` or `no-store` bypasses the cache.

**Still, restrict your backends.** Header-based identity is only as good as the network path. If an upstream is reachable directly, anyone who can reach it can set `Remote-User` themselves and quicgate never sees the request. Bind backends to the quicgate host, or firewall them to it.

**Sessions.** The SSO cookie is HMAC-signed with a per-install secret, `HttpOnly`, `SameSite=Lax`, and marked `Secure` whenever the client connection is HTTPS, including when TLS terminates on a proxy in front (`X-Forwarded-Proto`). It is bound to the exact host it was minted for, so a session for one host cannot be replayed against another that trusts different groups. Sessions are stateless: they cannot be revoked individually before they expire, so keep the lifetime modest for sensitive hosts. Rotating the provider, or **Profile → Sessions → Sign everyone out of SSO-protected hosts** (which replaces the signing key), invalidates every session at once. A changed or cleared `sso_cookie_secret` takes effect on the next reload, without a restart, and a restore applies the backup's key. Group membership is captured at login, so a group change takes effect at the next login (or when the session expires), while the host's allow-lists are re-evaluated on every request.

**Email verification.** A login is refused when the identity provider explicitly marks the address unverified (`email_verified: false`), so an IdP that lets users set their own address cannot be used to claim someone@your-domain and satisfy an allowed-domains rule. Providers that omit the claim are taken at their word.

**Empty policy means any authenticated user.** With no allowed emails, domains or groups, every account the IdP will authenticate gets in. That is fine for a private Keycloak realm and dangerous for a public IdP — set at least a domain or group rule when the provider is not exclusively yours.

**CORS preflights pass the gate.** An `OPTIONS` request carrying `Access-Control-Request-Method` reaches the upstream unauthenticated, by spec: preflights carry no credentials, and gating them breaks every cross-origin app. The real request that follows is gated normally, and identity headers are stripped from the preflight too.

**Admin API.** Failed logins are counted per client IP and the address is locked out after 10 failures in 15 minutes, covering the six-digit TOTP code as well as the password. Changing the password signs out every other session of that account (the session that made the change continues on a fresh id), **Profile → Sessions** signs out every other admin session on demand, a restore signs out all of them, and turning 2FA on or off asks for the current password again. The admin UI sets `SameSite=Strict` session cookies, applies a same-origin check to cookie-authenticated writes, and serves a strict CSP. Credentials for other systems (the IdP client secret, DNS provider keys) are never returned by the settings API: reads show a mask, and sending the mask back keeps the stored value.

**Admin SSO is authorisation, not just authentication.** Admin login through OIDC or LDAP admits an external identity only when it has a local account with the same address or is named in the allow-list (`oidc_allowed_emails`, `ldap_allowed_users`). An empty list matches nobody: a successful login at your IdP or directory proves who someone is, not that they should administer the proxy. The admin OIDC login uses PKCE (S256) and a nonce, and each sign-in can be completed once, within five minutes of starting it. Password login always keeps working, so a misconfigured IdP cannot lock you out. LDAP requires `ldaps://` (a plain bind would put the admin password on the wire in clear text), and directory users do not inherit local TOTP, so require MFA at the directory.

**Backups are as sensitive as the database.** An export contains password hashes, TOTP seeds, API-token digests, IdP client secrets, DNS credentials and certificate private keys, none of it encrypted at application level. Store exports the way you would store the data volume. Restore uploads are bounded (200 MiB compressed, 2 GiB expanded) and reject anything but the files a backup produces.

**API tokens are administrator credentials.** They do not expire, carry no scopes, skip interactive 2FA, and can read backups or rewrite routing. Issue them for a purpose, and delete them when that purpose ends.
**Never expose the admin port.** Port 81 behind an access list, VPN or firewall, always.
