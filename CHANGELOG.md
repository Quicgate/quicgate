# Changelog

All notable changes to quicgate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.17.1] - 2026-09-18

### Changed
- **The VPN page shows everything it can do, from the start.** In 1.17.0 the parts about people
  (logins, LAN access, policies) stayed hidden until a portal host existed, the "VPN only" option
  was hidden in the host editor until WireGuard was on, and the portal was only findable as a
  host type. With WireGuard off that left a page with two empty tables and no hint of the rest.
  Now the page opens with a map of the four parts in the order they build on each other (the
  endpoint, sites, devices and VPN-only hosts, people with the portal and LAN access), each with
  its state, what it still needs, and links to the right place, including "Add a VPN portal
  host". Every section is always there and says what it is for while it is empty.
- "VPN only" is always shown in the host editor. While WireGuard is off it is disabled and says
  so, because a VPN-only host would then be reachable by nobody.

## [1.17.0] - 2026-09-18

The rest of the WireGuard work in SPEC-wireguard.md: Release B (devices and a private entrance)
and Release C (single sign-on for the VPN, LAN access). Everything here is off until you use it,
and an install that does not switch WireGuard on runs none of it. The new **VPN guide** in the
built-in help describes all of it.

### Added
- **Hosts that exist on the VPN only.** Tick "VPN only" on a host and it is served inside the
  WireGuard tunnel and nowhere else. On the public listeners the name is answered like a name
  quicgate has never heard of, in HTTP and in the TLS handshake. Devices find such hosts without
  DNS work: quicgate is the DNS server inside the tunnel and answers its own names itself.
- **Devices.** Add a phone or a laptop on the VPN page. The browser makes the keypair, the
  configuration is shown once and can be downloaded as a `.conf` file. Revoking is final: the key
  can never be registered again and open connections are closed at once.
- **VPN rules in access lists:** a fourth kind of rule that says who is at the other end of the
  tunnel (anyone, a site, a device, a group, a person). A request from outside the tunnel never
  matches one, and a request from inside never matches an IP or country rule, so switching the
  VPN on cannot change who passes a list you already have.
- **The VPN portal**, a new host type. People log in with single sign-on and add their own
  devices. The login must be fresh (`max_age` and a checked `auth_time`) and must come with a
  refresh token; quicgate then asks the identity provider again every few minutes. A refusal
  takes the person's devices off at once and closes their connections; an outage extends
  nothing; after 30 days the person logs in again. Admins can end a login or block a person.
- **LAN access (experimental).** People who logged in reach the destinations their policies
  name, on the networks the quicgate machine is on. quicgate is not a router: it terminates each
  connection in its userspace stack and opens a new one, so nothing on the LAN can reach a
  device and devices cannot reach each other. Loopback, link-local, multicast, the tunnel itself
  and every listener of quicgate are refused whatever a policy says, and this machine's own
  addresses are not covered by a route for the network they are in. Every flow is logged before
  it is allowed. In Docker on a bridge network, LAN access does not switch on until you list the
  host's addresses or confirm that no quicgate port is published in reach.
- **Break-glass devices** for the day the identity provider itself is what broke: LAN routes
  without a login. They take your password and a two-factor code, there are at most two, and
  they expire unless you state otherwise. The Overview page reminds you that they exist.
- The Overview's Attention list reports a WireGuard endpoint that does not run, break-glass
  devices, and dropped flow-log records.

### Fixed
- **A `GET` rule in an access list now covers `HEAD`.** Monitors and link previews send HEAD;
  they were refused by a list that allowed GET, and those refusals counted toward a ban.
- **A login prompt is not a ban strike.** The 401 that asks a browser for credentials, sent when
  none were given, no longer counts toward an automatic ban. Wrong credentials still do. Together
  with the previous item this removes the two ways an ordinary visitor's address could end up
  banned.
- A WireGuard site that calls in and had never been heard from made wireguard-go log an error
  every five seconds, for as long as the site was away. Keepalives now start when the site has
  been heard from.
- A dial-in site returns within seconds after quicgate restarts, instead of up to 40: quicgate
  remembers where each peer was last seen and calls it back.
- A tunnel address that a deleted site gave up was handed to the next site at once, which
  forces a rebuild of the network stack and drops every open tunnel connection. Freed addresses
  now stay out of use until the network has nothing else left.
- An identity provider can no longer be deleted while the VPN still names it.
- The key options in the "Add site" dialog were drawn with the browser's default white border,
  and the hints under several fields were unstyled.

### Notes
- LAN access is marked experimental in FEATURES.md until the code has had an outside review,
  and the portal is tested against a synthetic identity provider, not yet against a live
  Keycloak. The official WireGuard phone apps have not been tested by the project; the key
  format the browser produces is verified against the WireGuard implementation quicgate embeds.
- Still not built from SPEC-wireguard.md: the passphrase-wrapped key in backups and a
  key-rotation action (S36), and cancelling request contexts of requests in flight (S42; their
  connections are closed, which ends them).

## [1.16.0] - 2026-09-18

### Added
- **WireGuard sites: reach upstreams on networks quicgate is not on.** A site is an ordinary
  WireGuard peer at another location (a router, a small Linux box, a VPS) that fronts one or
  more networks. A proxy host, its pool and locations, and a stream can then be reached
  *through* that site. It also works the other way round: quicgate on a VPS, with the network at
  home calling in from behind carrier NAT. The endpoint runs inside quicgate (wireguard-go on a
  userspace network stack): no network device, no extra privileges, no change to the host's
  routing, still one static binary. Off by default; the new **VPN** page switches it on.
- A site's private key never reaches quicgate: the browser makes the keypair (or you paste a
  public key), and the site's configuration, with the preshared key quicgate adds, is shown
  once. The server's key and the preshared keys are sealed at rest like every other secret.
- The page shows each site's last handshake, traffic and open connections. With UPnP on, the
  UDP port is mapped on the router like 80 and 443.

### Security properties of sites
- **Never by address, never a fallback.** Traffic enters the tunnel only for an upstream that
  names a site. When the site or the tunnel is down, such an upstream answers 502: its address
  is never tried on the local network, where the same address can belong to another machine.
  An address outside the site's declared networks is refused before a packet is made.
- One connection pool per site. quicgate used one pool per host, and Go pools connections by
  address, so the same address behind a site and on the local network would have shared
  connections. A host may also not reach one address two ways.
- A network never changes hands inside the running VPN stack: giving a site a network another
  site had, or a new key, rebuilds the endpoint, which interrupts VPN traffic for a moment.
  Disabling or deleting a site closes the connections through it at once. A site that hosts or
  streams still use cannot be deleted.
- One site's problem stays that site's: an endpoint name that does not resolve leaves the
  endpoint and the other sites running, and names are looked up again every five minutes, so a
  dynamic-DNS endpoint is followed.

### Good to know
- A site without an endpoint has to call quicgate. After quicgate restarts such a site needs up
  to 40 seconds to come back, and hosts behind it answer 502 until then. A site with an endpoint
  is back at once. Give a site an endpoint wherever it has a reachable address.
- The site's own router must forward between the tunnel and its network (IP forwarding, and a
  return route or NAT). See the Streams & port forwards guide.
- The image grows from about 28 MB to about 34 MB.

## [1.15.0] - 2026-09-18

### Security
- **Secrets in the database are encrypted at rest.** Until now the database held them in the
  clear: the admin's two-factor (TOTP) secret, OIDC client secrets, DNS provider credentials,
  the private keys of uploaded and self-signed certificates, and the key that signs SSO cookies.
  A leaked `quicgate.db` or backup archive handed all of them over. They are now sealed with
  XChaCha20-Poly1305, each value bound to its own row and column so a ciphertext copied elsewhere
  does not open. The first start of this version seals everything that is stored, then rewrites
  the database file, because replacing a value in SQLite leaves the old bytes in free pages and
  in the write-ahead log. Passwords, basic-auth passwords and API tokens were hashes already.
- The key comes from `QG_SECRET_KEY_FILE` or `QG_SECRET_KEY`; without either, quicgate creates
  `secret.key` in the data directory. A key in the data directory protects against a leaked
  database or backup, not against someone who can read the whole directory: keep the key
  elsewhere if that matters to you. **Backup archives never contain the key.** Keep a copy of it
  with your backups, stored separately; a restore on another machine needs it.
- **A missing or wrong key locks the secrets, it never replaces them.** quicgate still starts and
  proxies. Sealed values are kept untouched, no new key is invented, and what needs a secret
  fails closed: OIDC sign-in, DNS-01, hosts on a custom certificate, and any login for an
  account with two-factor (an unreadable 2FA secret is never read as "2FA is off"). The
  Overview says so under Attention. Put the key back and restart.
- Restoring a backup from an older version seals what it brings in. Restoring one that another
  instance sealed keeps those values as they are and warns that its key must be added to the
  key file (one key per line; the first line seals, all lines open).

### Upgrade note
- **Rolling back:** a version before this one reads a sealed value as if it were the secret, so
  certificates fail to load and OIDC logins fail (closed, not open). Before starting an older
  version, run `quicgate -unseal` once: it writes the secrets back in plaintext and exits.

## [1.14.1] - 2026-09-18

### Fixed
- "Never ban my own addresses" no longer counts link-local addresses, and
  Settings shows how many addresses of this machine it covers (the full list
  is in the tooltip) instead of printing them all. On a Docker host that was
  one address per container interface.

## [1.14.0] - 2026-09-18

### Added
- **A never-ban list for auto-ban.** Settings, Auto-ban has a list of addresses
  and CIDR ranges that are never banned, and a switch "Never ban my own
  addresses" that covers this machine's addresses and the router's public
  address (learned over UPnP, and followed when it changes). Devices at home
  that open a public hostname arrive from the router's public address, so one
  monitor sending requests an access list refuses could ban the whole
  household from every host. Access lists still apply to these addresses;
  they are only never banned. Putting a banned address on the list lifts its
  ban straight away. A list with a typo is refused instead of half applied.
  `GET /api/own-addresses` shows which addresses the switch covers.

## [1.13.0] - 2026-09-15

### Changed
- Bans survive a restart or an upgrade. Auto-ban saves its bans to `bans.json`
  in the data directory whenever a ban starts or is lifted, and at shutdown,
  and restores them at startup, leaving out the ones that expired in the
  meantime. Before, every restart lifted all bans.

## [1.12.1] - 2026-09-15

### Fixed
- Browser password managers no longer fill the saved admin login into the
  Logs and Proxy hosts search boxes, or into other settings fields. The search
  boxes sit in forms of their own, the two-factor password fields in forms
  that name the account, and a basic-auth user's password in an access list
  counts as a new password for someone else, so the admin login is not
  offered there either.

## [1.12.0] - 2026-09-15

### Added
- **See who is banned and why.** Access control lists every address auto-ban
  is turning away: its country, the reason (address not allowed, no
  credentials or wrong credentials for which access list), the host it asked
  for, how many refusals led to the ban, when it started and when it lifts,
  with a button to lift a ban by hand. The Overview's Blocked tile and panel
  link there.
- `GET /api/bans` and `DELETE /api/bans/{ip}`.

## [1.11.1] - 2026-09-14

### Fixed
- Plain HTTP connections half-close again before closing a connection whose
  request body was not read (for example a refused upload), so the client
  receives the response instead of a reset. v1.11.0's byte counting had hidden
  that from the HTTP server.
- Traffic rates divide by the seconds of traffic a point actually holds, so the
  point spanning a restart, and the partial interval saved at shutdown, no
  longer read as a drop. Shutdown now records the traffic since the last
  sample.
- The login prompt a client without credentials gets from a basic-auth access
  list is no longer counted as blocked; wrong credentials still are.
- A refused UDP sender counts once a minute instead of once per packet.
- Paths closed because their single sign-on or forward auth is not configured
  are counted under that reason instead of access lists.
- HTTP/3 connections count only once their handshake completes, so spoofed
  handshakes do not inflate the connection numbers.
- Moving the start of a stream port range restarts the ports it shifts. Before,
  those ports kept forwarding to their old target port until a restart.
- A saved traffic history larger than the engine keeps is ignored instead of
  loaded.

## [1.11.0] - 2026-09-14

### Added
- **Traffic on the Overview.** quicgate now records its own traffic and the
  Overview charts it for the last hour, 6 hours, day or week:
  - Throughput in and out, measured on the client side of every listener
    (HTTP, HTTPS, HTTP/3 and streams), requests per minute by response status,
    and time to first byte at the 50th and 95th percentile.
  - A row of headline numbers with sparklines: outbound and inbound volume,
    requests, the server error rate, blocked requests, response time and open
    connections.
  - Open ports: every listener with its service, state, whether UPnP mapped it
    on the router, bytes in and out, connections and a traffic sparkline.
  - The busiest hosts, where requests come from (with a GeoIP database), the
    share of HTTP/1.1, HTTP/2 and HTTP/3, and what quicgate refused, by reason:
    access lists, auto-ban, rate limits, the exploit filter, bad bots, client
    certificates, single sign-on, forward auth and stream source filters.
  - The page follows along while it is open, every chart has a table view, and
    the history is kept in `traffic.json` in the data directory, so a restart
    or an upgrade does not wipe it.
- `GET /api/traffic?range=1h|6h|24h|7d` serves that history, and
  `GET /api/overview` reports when the engine started.
- Prometheus metrics per listener (`quicgate_listener_received_bytes_total`,
  `quicgate_listener_sent_bytes_total`, `quicgate_listener_connections_total`,
  `quicgate_listener_open_connections`), requests by HTTP version
  (`quicgate_requests_by_protocol_total`) and refusals by reason
  (`quicgate_blocked_total`).

### Changed
- The Overview's configuration numbers moved to a Configuration panel below the
  traffic, and the Listeners panel became the Open ports table.

### Fixed
- An informational response such as 103 Early Hints was logged as the request's
  status. The access log now records the final status.

## [1.10.0] - 2026-09-13

### Changed
- **A more deliberate admin interface.** The layout now reads like an
  operations console instead of a demo:
  - Account, appearance and sign-out live in a menu under the signed-in user at
    the top right. The profile page became an Account page (password and 2FA,
    sessions, API tokens) reached from that menu.
  - Every page has a header with its title, a short summary and its main
    action, instead of action buttons in the top bar.
  - Settings is split into sections (General, Certificates, Client IP & GeoIP,
    Auto-ban, Notifications, Admin sign-in, Backup & restore), each a panel of
    labelled rows with an explanation per field. Saving reports success or the
    server's error in the panel, instead of a browser alert.
  - The System page is now Logs: one viewer for traffic that matched no host,
    all traffic or a single host, with search, status filters and paging,
    instead of hundreds of rows on one long page. A host's Logs button opens it
    for that host. The page and section are kept in the URL, so a reload stays
    where you were.
  - The effective-configuration table is gone. What it added over the host list
    (routes that fail closed) is now shown on the affected host rows and on the
    Overview.
  - The Overview shows the key numbers, a list of what needs attention
    (unreachable upstreams, failed certificates, routes that fail closed,
    streams that are not running, disconnected Docker hosts) and plain lists of
    listeners and features, instead of charts and on/off tiles.
  - Tables use quieter badges, and destructive buttons only turn red when you
    point at them.

[1.10.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.10.0

## [1.9.1] - 2026-09-13

### Changed
- Built with Go 1.27.1: the digest-pinned build image and the toolchain pin in
  `go.mod` move together, and building from source now needs Go 1.26 or newer.
- Dependency updates: quic-go 0.62.0 (HTTP/3), go-oidc 3.21.0,
  klauspost/compress 1.20.0, golang.org/x/crypto 0.57.0, golang.org/x/oauth2
  0.37.0, golang.org/x/time 0.16.0 and modernc.org/sqlite 1.58.0.
- CI refuses a build image whose Go version differs from the toolchain pinned
  in `go.mod`, so a release is always built with the Go that was tested and
  scanned, and the provenance attestation now also records where the image is
  stored.

[1.9.1]: https://github.com/Quicgate/quicgate/releases/tag/v1.9.1

## [1.9.0] - 2026-09-13

Security remediation from an independent review of v1.8.1 (findings Q01 to
Q16), plus the defects that two further independent checks of that remediation
found. Every fix ships with a regression test that fails when the fix is removed.

### Security
- **Client certificates are bound to the requested host (Q01).** The TLS
  handshake picks the client-certificate policy from the SNI name, but the
  request was routed by its Host header, so a connection opened for a public
  name could ask for a certificate-protected host and be served. A request is
  now refused with `421 Misdirected Request` whenever its SNI selects a
  different host and either side takes client certificates (this also covers
  HTTP/2 and HTTP/3 connection reuse), and the certificate is verified again
  against the requested host's current CA on every request, so replacing a CA
  applies to connections that are already open. A client-certificate host is
  never served over plain HTTP, whatever its force-SSL flag says. A CA bundle
  that does not parse is now rejected when saved, and one already in the
  configuration closes the host instead of silently dropping the requirement.
  Client certificates on a `certMode: none` host are refused.
- **Per-path SSO policies on the same identity provider are kept apart
  (Q02).** Gates were shared by provider id, so a stricter `/admin/` rule on
  the same IdP as the host inherited the host's broader allowed groups, emails,
  domains and passIdentity. Each distinct policy now gets its own gate (they
  still share discovery and token verification), every request is authorised
  against the policy of the rule that matched it, and the login callback is
  finished by the gate that started the login.
- **The response cache never crosses identities (Q03).** The cache key held
  only method, host and URI, so a personalised response could be replayed to
  another user. Requests that carry a cookie, arrived with an Authorization
  header (even one an access list stripped), or were admitted by an identity
  gate (basic-auth user, SSO session, forward auth) now bypass the cache
  entirely. The key also varies on the normalised Accept-Encoding, so a
  compressed upstream body is never replayed to a client that did not ask for
  it; any other `Vary` is not cached; request `Cache-Control: no-cache` and
  `no-store` are honoured; `max-age=0` and `s-maxage=0` responses are not
  stored.
- **A DNS failure can no longer open an access list (Q04).** A hostname rule
  that failed to resolve was dropped, and an access list left with no rules was
  treated as unrestricted. Hostname rules now keep their last resolved
  addresses for up to 24 hours while DNS is failing; after that, or with no
  earlier answer, an unresolved allow rule matches nobody and an unresolved
  deny rule denies everyone who reaches it. Country rules behave the same way
  when the GeoIP database is not loaded. The effective-config view shows these
  conditions as warnings on the affected routes.
- **Missing security references fail closed (Q05, engine side).** A host
  naming a deleted access list was served without one, and a path rule naming
  a deleted access list, forward auth the host does not configure, SSO without
  a provider, or an unknown mode fell back to the host's own gate, which may be
  public. All of these now refuse every request on the affected host or path.
- **References are checked in one place, and in-use objects cannot be
  deleted (Q05).** Deleting an access list only checked host-level use, so a
  list still used by a path rule or a stream could be removed. The store now
  refuses to delete an access list, certificate or identity provider while any
  host, path rule, stream or the admin login uses it, and refuses to store a
  host or stream that names one that does not exist. The checks run in the
  store itself, so import, Docker adoption and every other writer get them, not
  only the admin API. A Docker container whose `quicgate.access-list` label
  names a list that does not exist is no longer routed without it; it is not
  routed at all.
- **Streams fail closed (Q07).** A TLS-terminating stream whose certificate
  was missing became a plaintext forwarder, and an access list reused as a
  stream filter kept only its allow CIDRs, dropping deny rules and leaving the
  stream open when nothing usable remained. Streams now evaluate the whole
  ordered list (an allow limited to HTTP methods never opens a connection, a
  deny limited to methods still closes it, a list that needs basic-auth
  credentials admits no connection), a configured filter that yields nothing
  keeps the stream closed, and a stream that cannot run safely is not started.
  Replacing a stream's certificate restarts its listener with the new one.
- **PROXY protocol is only believed from trusted peers (Q08).** Any client
  could claim an allowed source address by sending a PROXY header. Accepting
  PROXY protocol now requires a list of trusted proxies: a trusted peer must
  send a valid v1 or v2 header within 5 seconds, and any other peer connects as
  itself, with its own address checked and nothing it sends parsed as a header.
  **Action needed:** a stream with *Accept inbound PROXY header* enabled and no
  trusted proxies does not start until you add them.
- **Credential changes end live sessions (Q11).** Changing the admin password
  left other sessions signed in, and replacing the SSO signing key did nothing
  until a restart. A password change now signs out every other session of the
  account (the caller continues on a fresh session id), a new *Sessions* card
  can sign out every other admin session and sign every user out of all
  SSO-protected hosts, a changed or cleared SSO signing key applies on the next
  reload, and turning 2FA on or off asks for the current password.
- **Admin OIDC login binds the sign-in (Q12).** The admin login now sends a
  PKCE (S256) challenge and a nonce, keeps each sign-in as a one-use server-side
  record valid for five minutes, checks the nonce in the ID token, marks the
  state cookie `Secure` on HTTPS and scopes it to `/api/oidc/`, and bounds every
  request to the IdP with a timeout (application SSO requests are bounded too).
- **Request data is never rendered as HTML in the admin UI (Q13).** The log
  viewer inserted the request path, Host and method a remote client chose
  straight into the page. Those, and every other value that comes from the API
  (certificate errors, custom certificate names, host targets, effective
  configuration), are now escaped, and the escaping helper covers single quotes
  as well.
- **Bounded state for public traffic (Q14).** Per-host metrics are labelled by
  configured route, with one `_unmatched` label for everything else, so invented
  Host headers no longer grow the metrics without limit. Rate limiting, bad-bot
  and exploit filtering now run before the authentication gates, and the
  rate-limit, auto-ban and login-throttle tables have hard size caps.
- **Stream resource limits (Q14, streams).** Each UDP listener keeps at most
  1024 client sessions, each TCP listener at most 4096 concurrent connections,
  and TLS-terminating streams allow 10 seconds for the handshake.
- **Reproducible, scanned and attested releases (Q15).** The build used a
  mutable `golang:1.26-alpine` image and whatever Go CI picked, and six
  reachable standard-library advisories affected Go 1.26.5 builds. `go.mod`
  now pins `toolchain go1.26.8` and CI fails if the runner's Go differs, the
  build image is pinned by digest (Dependabot keeps it current), a
  `govulncheck` job gates the image build on zero reachable vulnerabilities,
  and every published image gets signed build provenance
  (`gh attestation verify oci://ghcr.io/quicgate/quicgate:<tag> --owner Quicgate`).
- **Spoofed identity headers are stripped on every path (Q06).** Inbound
  `Remote-User`, `Remote-Email` and `Remote-Groups` were only removed on hosts
  with host-level SSO. They are now removed on any host with an SSO gate on
  any path, and forward-auth response headers are removed host-wide, so public
  carve-outs cannot pass forged values to an upstream that trusts them.
- **An SSO login-state cookie is no longer accepted as a session.** The
  short-lived state cookie that every anonymous visitor receives when a login
  starts was signed with the same key as the session cookie, and its JSON
  shares the session's host, expiry and provider fields. Renamed to the session
  cookie, it opened any host whose SSO policy admits every authenticated user,
  without a login. Both cookies are now signed for their own purpose. Existing
  SSO sessions and logins in progress become invalid once on upgrade, so users
  of SSO-protected hosts sign in again.
- **The response cache also bypasses client certificates and reads every
  Cache-Control field.** Two clients presenting different client certificates
  could share a cached response, and a `private` or `no-store` directive in a
  second `Cache-Control` header field was ignored.
- **Restore refuses files that are not quicgate backups.** Any valid SQLite
  file was accepted, and because tables missing from a backup are emptied (and
  tables that share no columns with the schema restore no rows), it wiped the
  configuration and the admin account. A restore that would leave no admin
  account able to sign in is refused too: it would lock the operator out, and
  the next start would recreate the default credentials.
- **CORS preflights no longer pass address rules.** A preflight skipped the
  whole access list, so any client could send `OPTIONS` requests to a backend
  behind an IP allowlist, even one that fails closed. Preflights still skip
  the basic-auth check (they cannot carry credentials), but address, hostname
  and country rules now apply to them, evaluated for the method the preflight
  announces.
- **The admin sign-in provider fails closed.** `admin_oidc_provider_id` accepted
  an id that does not exist, and when the provider it named was gone, admin
  OIDC sign-in silently used the inline issuer settings instead. The setting is
  now validated, and a missing provider stops OIDC sign-in with an error.
- **A sign-in cannot outlive a password change it raced.** A login that
  verified the old password while the password was being changed could still
  create its session after the change had signed everyone out. Sessions are now
  only created while the account's password and second factor are the ones the
  login checked.
- **Changing a stream closes the connections it admitted.** A TCP connection
  accepted before a source restriction was added kept its access until it
  closed by itself. When a stream's settings change, or it is disabled or
  removed, its open connections are now closed with the old listener.
- **An auto-ban notification can no longer freeze the proxy.** The webhook was
  called while holding the lock every request takes, so with auto-ban and a
  notification URL set, each ban stalled all traffic on all hosts for as long
  as the webhook took (up to 10 seconds), repeatable by anyone who can fail a
  login. Notifications are now sent in the background, and the auto-ban
  settings are applied at reload instead of being read from the database on
  every request.
- **Identity headers are stripped under every spelling.** `Remote_User` (or
  any case of it) passed the strip and reached the upstream, and many
  application servers read it as the same variable as `Remote-User`. The same
  applies to forward-auth response headers.
- **UDP streams cap sessions per source address** (64), so one sender cannot
  fill a listener's 1024 sessions and lock every other client out.
- **Idle keep-alive connections on the public listeners close after 2
  minutes** instead of being held open indefinitely.
- **Restore checks the certificate entries and every row it restores.** A
  regular file named `certs/` in an archive replaced the certificate directory
  with a file while reporting success, and a backup whose access-list rules do
  not decode was committed and broke every reload. Both are refused.
- **Import never silently removes protection, and binds the document's own
  access lists.** An entry matching an existing host, stream or access list
  replaced it whole, so a document that left out a host's access list, SSO or
  path gate made it public. Such an import is now refused with the reason. An
  access list `id` in the document now refers to the list that document
  defines; before, a host was bound to whatever list had that id in the
  database.

### Changed
- A Host header or SNI with a trailing dot (`example.com.`) now routes to the
  same host as `example.com` instead of being an unknown name.
- The access-log viewer skips an entry longer than 1 MiB instead of stopping
  at it; a single request with a huge path used to hide every later entry.
- Requests to an identity provider reuse pooled connections; with
  certificate verification skipped, every login leaked a transport.
- **A replaced or restored custom certificate is served right away.** The
  certificate cache kept every certificate it had loaded, so after replacing a
  custom certificate's PEM (or restoring a backup) the TLS listener could go on
  serving the old one until a restart. Reload now unloads the certificates that
  are no longer current.
- **Stream listeners report whether they run (Q09).** A saved stream could fail
  to start (a port another process holds) with only a log line to show for it.
  `GET /api/streams` and the stream create and update responses now include a
  `listeners` array with `state` (`running` or `failed`) and the error, the
  stream list shows *not running*, and the stream dialog stays open with the
  reason when a saved stream cannot run.
- The stream guide no longer claims managed ACME certificates work for TLS
  termination on streams; only custom certificates do.
- **Import is atomic and repeatable (Q09).** `POST /api/import` wrote entries
  one by one and stopped at the first error, leaving the earlier ones stored
  but not applied, and importing the same access list twice failed on its
  unique name. The whole document now applies in one transaction or not at all,
  and entries matching existing configuration (access lists by name, hosts by
  domain set, streams by listen port and protocol) are updated in place. The
  response keeps the created counts and adds an `updated` object. Unknown fields
  in the document are now rejected like everywhere else in the API.
- **Restore reproduces the backup, or changes nothing (Q10).** Restore copied a
  fixed list of tables that missed API tokens and port forwards (so tokens
  created after the backup survived and the backup's own were lost), ignored
  certificate copy errors, left stale certificate files, and still reported
  success. It now replaces every table in the schema (emptying tables an older
  backup lacks, matching columns by name), swaps the certificate tree in as a
  unit with rollback, refuses a snapshot that fails SQLite's integrity check,
  reports any failure without changing anything, returns warnings for dangling
  references, and signs out every admin session afterwards. Backup export builds
  the archive completely before sending it, so a read failure is an error
  instead of a truncated download.
- **Graceful shutdown on SIGTERM (Q16).** Only Ctrl-C triggered the shutdown
  path, so `docker stop` killed the process without closing listeners,
  releasing UPnP mappings or flushing the access log. SIGTERM now shuts down
  the same way, and the access log is flushed on exit.
- **Claims match what is built (Q16).** A new [FEATURES.md](FEATURES.md) tracks,
  per feature, whether it is tested locally, qualified against real
  infrastructure, deferred or a non-goal. The roadmap no longer says every item
  is fully proven, the spec no longer promises encrypted key storage, roles or
  an audit log that do not exist, the API reference no longer calls `/metrics`
  unauthenticated, from-file certificates are documented as read once, the
  per-host HTTP/3 switch is documented as advertisement-only, and the
  benchmark wording no longer claims the proxy is never the bottleneck.
- **Behaviour changes to note:** requests from clients over a host's rate limit
  are now refused before authentication (they no longer reach the login
  prompt), `POST /api/2fa/enable` and `/api/2fa/disable` require a `password`
  field, CORS preflights from addresses an access list does not admit get
  `403`, users of SSO-protected hosts sign in once more after the upgrade, and
  editing a stream reconnects its clients.

[1.9.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.9.0

## [1.8.1] - 2026-08-23

### Changed
- **The theme picker is a real menu.** It was a native `<select>`, whose
  dropdown is drawn by the operating system and ignores the app's palette —
  a bright blue row in the middle of a dark UI. It is now a themed popover
  where each entry previews the theme it selects (surface colour plus accent),
  ticks the active one, and closes on Escape or an outside click.
- **Settings is grouped and only shows what applies.** The eight cards sat in
  one flat grid with every field for every feature visible, configured or not,
  which left tall/short cards next to each other and a lot of empty inputs to
  read past. They are now grouped under *Certificates*, *Who can administer
  quicgate*, *Traffic handling* and *Data*, and the OIDC, LDAP and auto-ban
  cards keep their fields hidden until the feature is switched on. Choosing a
  shared identity provider also hides the inline issuer/client/secret fields
  it replaces. A default install now shows half the inputs it used to.

[1.8.1]: https://github.com/Quicgate/quicgate/releases/tag/v1.8.1

## [1.8.0] - 2026-08-23

### Added
- **Theme chooser with a second theme.** The top bar gains a theme picker
  next to the light/dark toggle. **Console** stays the default and is
  unchanged; **Brass & Iron** is a warm-metallic alternative — brass, copper
  and aged iron surfaces, Playfair Display for headings, Lora for body text,
  JetBrains Mono for data, and a thin brass edge along the top of each card.
  Each theme has its own light variant, so there are four combinations, and
  both choices persist and are applied before first paint.
  The theme is token overrides scoped to `html[data-skin="brass"]`, so
  components pick it up without their own rules changing. All three
  typefaces are vendored as variable fonts (107 KB total): the admin origin
  serves a strict CSP and has to keep working offline, so nothing is fetched
  from a font CDN — and for the same reason the pre-paint theme script is a
  file rather than an inline `<script>`.
- **Per-path identity providers.** A `mode: oidc` path rule can now name its
  own provider and policy instead of inheriting the host's, so one host can
  gate `/staff` with the company IdP and `/partner` with another, or use a
  separate app registration per URL on the same IdP. Every provider redirects
  back to the one callback path; the signed state cookie records which login
  is in flight, so the gate that started it finishes it.
- **The admin login can reuse a provider entry.** Settings gains an identity
  provider picker (`admin_oidc_provider_id`) listing the same providers the
  hosts use, instead of repeating issuer, client id and secret in its own
  fields. Those fields remain the fallback, so existing setups are untouched,
  and the admin allow-list stays separate either way.

### Security
- **SSO sessions are now bound to the issuing provider.** They were bound to
  the host only, so once a host could reference two providers, a session
  obtained from the less trusted one satisfied a path gated by the more
  trusted one: get an account wherever you can, walk in everywhere. Sessions
  carry the provider id and a gate accepts only its own. Existing sessions do
  not carry it and are re-authenticated once.
- Deleting a provider is refused while a path rule or the admin login still
  references it, matching the existing check for hosts.

### Fixed
- The host modal's OIDC provider pickers were empty unless the Access Lists
  page had been opened first, so saving a host from that state silently
  dropped the provider it was using. The hosts page loads providers itself.

[1.8.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.8.0

## [1.7.2] - 2026-08-23

### Security
- **Admin OIDC login admitted anyone the provider would authenticate.** With
  `oidc_allowed_emails` empty, `emailAllowed()` returned true for every
  address, so enabling admin SSO against a tenant you do not exclusively
  control handed full proxy administration to every account in it. An external
  identity now needs either a local account with the same address or an
  explicit allow-list entry; an empty list matches nobody. Password login is
  unaffected, so this cannot lock anyone out.
- **Admin OIDC ignored `email_verified`.** The claim was parsed and never
  read. A provider that lets users choose their own address could therefore be
  used to claim an administrator's address. A login is now refused when the
  provider explicitly marks the address unverified.
- **Any directory user could administer the proxy over LDAP.** A successful
  bind was treated as authorisation, so every account in a corporate directory
  held root over the ingress. Binding now only proves the password;
  administering also requires a local account or an entry in the new
  `ldap_allowed_users` list.
- **LDAP used filter escaping on a distinguished name.** `EscapeFilter`
  escapes search-filter metacharacters and leaves `,`, `=`, `+` and friends
  alone, so a crafted username could restructure the DN it was spliced into.
  Now `EscapeDN`, as the value's context requires.
- **LDAP binds refuse plaintext transport.** `ldap://` sent the admin password
  in clear text; `ldaps://` is now required, with a 5s dial and 10s operation
  timeout so a hung directory cannot pin a login request.
- **Restore could be used as a decompression bomb.** The upload limit bounded
  the compressed body only, so a few megabytes of zeroes could expand without
  bound and fill the data volume. Expansion is now capped at 2 GiB, and
  archives carrying duplicate or non-regular (symlink, device) members are
  rejected.
- Admin sessions minted by OIDC now get the same cookie treatment as password
  logins: `SameSite=Strict` and `Secure` on HTTPS, instead of `Lax` and never
  `Secure`. Entropy failures when minting the session id are no longer ignored.

### Fixed
- `/api/me` returned 500 for an approved OIDC/LDAP identity with no local
  database row, breaking the UI right after a successful external login. It
  now reports the session identity and no local 2FA.
- An LDAP user who also has a local account keeps that local identity on the
  session, so the forced password change, 2FA and the profile page resolve to
  the real account instead of an `ldap:`-prefixed stand-in.

[1.7.2]: https://github.com/Quicgate/quicgate/releases/tag/v1.7.2

## [1.7.1] - 2026-08-23

### Security
- **Path traversal could walk out of a public path rule.** A request for
  `/public/../admin` matched a `public` auth rule on its raw path, while an
  upstream that resolves dot segments (nginx, Apache, IIS, most frameworks)
  served `/admin` — bypassing the host's access list, forward auth or SSO.
  Any path containing a `.` or `..` segment is now refused with 400 before it
  reaches a gate, a path rule, a custom location or an upstream. Whole
  segments only, so `/.well-known/acme-challenge/...` and `/file.tar.gz` are
  unaffected. Encoded forms (`%2e%2e`) are covered, since matching happens on
  the decoded path.
- **Forward-auth hosts passed client-supplied identity headers.** The headers
  listed under *Copy response headers upstream* were only overwritten when the
  auth server returned a non-empty value, so a 2xx response that omitted
  `Remote-User` let the client's own `Remote-User` reach the upstream. Those
  headers are now stripped from the inbound request before the auth subrequest
  and before the upstream sees it. (OIDC hosts already stripped them.)
- **SSO session cookies were not marked Secure behind a TLS-terminating
  proxy.** `Secure` was set from `r.TLS` alone, so with TLS terminating on a
  load balancer in front of quicgate the session cookie could ride a plain
  HTTP hop. It now honours `X-Forwarded-Proto`, as the OIDC redirect URI
  scheme does — which also fixes redirect-URI mismatches in that deployment.
- **Unthrottled admin login.** A wrong password cost a flat 400ms and nothing
  else, and the six-digit TOTP code had no limit at all, so an attacker
  holding the password could walk the code space. Failed logins are now
  counted per client IP, with a 15-minute lockout after 10 failures in 15
  minutes, covering password, LDAP and TOTP failures alike.
- **Credentials echoed by the settings API.** `GET /api/settings` returned the
  admin OIDC client secret and the DNS provider config (which holds a private
  key) in cleartext to any session or API token, putting them in the browser
  and in any exported HAR. Both are masked on read; sending the mask back
  keeps the stored value.

### Fixed
- The OIDC login callback is now always routed to the SSO gate. A host that
  gated only some paths with SSO sent the browser to the IdP and then handed
  the redirect back to whichever path rule matched `/.qg/oidc/callback`, so
  the session was never minted and the user looped through login.
- A login is refused when the IdP explicitly marks the address unverified
  (`email_verified: false`), so a self-set address cannot satisfy an
  allowed-domains policy.
- The post-login redirect target rejects backslashes and CR/LF in addition to
  protocol-relative paths.

[1.7.1]: https://github.com/Quicgate/quicgate/releases/tag/v1.7.1

## [1.7.0] - 2026-08-23

### Added
- **Built-in OIDC SSO.** A proxy host can now require an OpenID Connect login
  served by quicgate itself, replacing the Pomerium/Authelia/oauth2-proxy
  sidecar for the common case. Identity providers (Keycloak, Entra ID,
  Authentik, any spec-compliant IdP) are defined once under **Access Lists ->
  Identity providers** and referenced per host; quicgate runs the auth-code
  flow with PKCE and a nonce, keeps a stateless HMAC-signed session cookie
  that is bound to the exact host it was minted for, and enforces a per-host
  policy of allowed emails, domains and/or groups (from a configurable groups
  claim). The identity can be passed upstream as `Remote-User` /
  `Remote-Email` / `Remote-Groups`; inbound copies of those headers are
  always stripped, on public paths too, so they can never be spoofed through
  quicgate. Gated hosts reserve `/.qg/oidc/callback` (the redirect URI to
  register at the IdP) and `/.qg/oidc/logout`. IdP discovery is lazy and
  cached, so config reloads never block on the IdP, and a host whose
  provider was deleted fails closed with 403. Providers are managed via
  `/api/oidc-providers` (client secret masked in responses; an empty secret
  on update keeps the stored one) and included in backups.
- **Path authentication.** A proxy host's access list and forward auth used to
  gate the whole host; they can now be overridden per URL. Each rule is a path
  (prefix or exact), a mode (`public`, a named access list, the host's
  forward auth, or the host's OIDC SSO) and optional HTTP verbs, and the longest matching path wins.
  Anything matching no rule keeps the host's own gate. This covers the case a
  reverse proxy in front of SSO always runs into: a licensing callback, webhook
  receiver or health probe that has to answer without credentials while the
  rest of the host stays behind authentication. Rate limits, bad-bot and
  exploit filters remain host-wide, so a public path is still protected from
  abuse. Editable under **Security -> Path authentication** in the host modal;
  stored as `options.authRules`. A rule naming an access list that no longer
  exists falls back to the host's gate instead of opening the path, and the API
  rejects such a reference on write.
- **Built-in guides.** The Help page now opens with five markdown guides
  (getting started, configuration reference, access control & SSO, Docker
  labels, streams & port forwards) rendered by a small vanilla markdown
  renderer, embedded in the binary and fully offline. The same files live in
  `web/docs/` on GitHub, and the README slimmed down to a pitch that links to
  them.
- The Proxy Hosts table links each domain to the site itself (new tab), with
  the scheme taken from the host's certificate mode. Wildcard domains stay
  plain text since they have no single address to visit.

[1.7.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.7.0

## [1.6.1] - 2026-08-23

### Changed
- Dependency updates: `klauspost/compress` 1.19.1 -> 1.19.2 (gzip/zstd
  compression), `golang.org/x/crypto` 0.54.0 -> 0.55.0 and
  `modernc.org/sqlite` 1.55.0 -> 1.56.0 (the config store), plus the
  indirect bumps they pull in. No functional changes.

[1.6.1]: https://github.com/Quicgate/quicgate/releases/tag/v1.6.1

## [1.6.0] - 2026-08-04

### Added
- The Proxy Hosts table now shows backend health inline: a host whose
  upstream fails its health probe gets a red-tinted row and a `down` badge
  next to the upstream. Pool hosts keep their `N/N up` badge and pick up
  the same row tint when part of the pool is down. Uses the same health
  data as the Overview donut, refreshed every time the page is opened.

### Fixed
- HTTP/3 requests were proxied upstream as `Transfer-Encoding: chunked`:
  quic-go reports "unknown length" for bodyless requests, so every browser
  GET arriving over h3 was forwarded chunked, which strict upstreams (for
  example lighttpd) reject with 400 Bad Request before routing. Bodyless
  GET/HEAD requests are now normalized to an explicit empty body on both
  the host proxy and per-location proxies; POST/PUT bodies stream as
  before.

[1.6.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.6.0

## [1.5.3] - 2026-07-30

### Fixed
- **IPv6 literal upstreams and stream targets.** Addresses were built as
  `host:port`, which produces `2001:db8::1:8080` for an IPv6 literal — an
  address `net.Dial` rejects ("too many colons in address"). Health checks
  therefore marked every IPv6-literal backend permanently **down**, and IPv6
  stream forwards (and SNI-route targets) failed outright. All upstream, pool,
  location, stream and SNI addresses are now built with `net.JoinHostPort`, so
  they are correctly bracketed (`[2001:db8::1]:8080`). Hostnames that resolve to
  AAAA records were unaffected; only literal IPv6 addresses were.

[1.5.3]: https://github.com/Quicgate/quicgate/releases/tag/v1.5.3

## [1.5.2] - 2026-07-30

### Changed
- Dependency updates: `quic-go` 0.60.0 -> 0.61.0 (the HTTP/3 engine) and
  `modernc.org/sqlite` 1.54.0 -> 1.55.0 (the config store). No functional
  changes.

[1.5.2]: https://github.com/Quicgate/quicgate/releases/tag/v1.5.2

## [1.5.1] - 2026-07-24

### Changed
- Project moved to its own GitHub organization: **`Quicgate/quicgate`**. The
  container image is now **`ghcr.io/quicgate/quicgate`** (the old
  `ghcr.io/maferick/quicgate` path stops receiving updates; repoint your
  `image:` to the new one). No functional changes.

[1.5.1]: https://github.com/Quicgate/quicgate/releases/tag/v1.5.1

## [1.5.0] - 2026-07-24

### Added
- **Overview dashboard**: a new landing page with an at-a-glance summary —
  listeners, config counts (hosts by type, certificates, streams, access
  lists), health donuts (upstreams up/down, certificates issued/pending/failed,
  hosts by type), feature flags (HTTP/3, UPnP, auto-ban, GeoIP, forward-auth,
  OIDC, LDAP, Docker), and providers. One `GET /api/overview` call; vanilla
  inline-SVG donuts, no chart library.
- **Real client IP behind a trusted proxy** (Traefik #3097): when quicgate sits
  behind Cloudflare or another load balancer, set trusted-proxy CIDRs and a
  header (Settings) so access lists, GeoIP, rate limits and logs use the real
  client IP. A rightmost-untrusted `X-Forwarded-For` walk defeats client
  spoofing of the header.
- **Sticky sessions** (Traefik #1207/#1035): a per-host cookie affinity across a
  load-balanced upstream pool, so a client keeps hitting the same backend
  (the cookie carries an opaque id, never the upstream address).
- **Maintenance mode** (Traefik #3520): a per-host toggle that serves a 503
  "under maintenance" page (with `Retry-After` and an optional custom body)
  instead of proxying.
- **Response caching** (Traefik #878): a per-host TTL that caches cacheable
  GET/HEAD responses in memory (honouring `Cache-Control`, skipping `Set-Cookie`
  and authenticated requests), with an `X-Cache: HIT/MISS` header.

These four came from mining Traefik's most-reacted enhancement requests for
proxy-layer features that fit a homelab.

[1.5.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.5.0

## [1.4.0] - 2026-07-24

### Added
- **GeoIP status on the Settings page**: shows whether the GeoLite2-Country
  database is loaded (with its type and build date, or the exact expected path
  and error when missing), a **Recheck** button that re-opens the file with no
  restart, and a **test-an-IP** lookup so you can confirm country resolution
  actually works.
- Country access rules are now chosen from a **country picker** (the full list
  of ISO 3166-1 countries by name) instead of a free-text code, and the
  access-list editor warns when a country rule is used while GeoIP is not loaded.
  Country codes are also validated server-side.

### API
- `GET /api/geoip/status`, `POST /api/geoip/reload`, `GET /api/geoip/lookup?ip=`.

[1.4.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.4.0

## [1.3.0] - 2026-07-24

### Added
- **Multiple Docker hosts**: the label provider can watch several daemons at
  once. Configure a JSON list of endpoints (`QG_DOCKER_ENDPOINTS`, or the
  **Docker hosts** box on the Docker page), each with a name, a connection (a
  local socket path or `tcp://host:port`, e.g. a read-only socket proxy), and
  the address where that host's published ports are reachable. The Docker page
  shows each host's connection state and labels every container with its host.
- The Docker client now speaks `tcp://` endpoints in addition to unix sockets.

### Changed
- **Simpler connect model**: quicgate now always reaches a container at the
  Docker host's address on its published port (a `network_mode: host` container
  at that port directly). The `auto` / `network` / `published` connect-mode and
  the shared-network container-IP path are gone; `quicgate.port` still names the
  container's internal port, so publish the port you want routed. Removes the
  `docker_connect_mode` and `docker_host_address` settings (endpoints carry the
  address now).

[1.3.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.3.0

## [1.2.0] - 2026-07-24

### Added
- **Docker label provider** (opt-in via `QG_DOCKER=1`): derive proxy hosts and
  TCP/UDP streams from container labels — Traefik's provider idea with a flat
  label set, no router/service/middleware graph.
  - Labels: `quicgate.enable`, `quicgate.host`, `quicgate.port`,
    `quicgate.exclude-ports`, `quicgate.scheme`, `quicgate.tls-skip-verify`,
    `quicgate.tls`, `quicgate.access-list`, and `quicgate.streams` (raw L4
    forwards). Stream ports are excluded from web-port auto-detection, so a
    container with a web port and a game/DB port needs no manual excludes.
  - Optional `QG_DOCKER_DOMAIN` derives the hostname from the container name.
    Access lists are reused by name. A container can be HTTP-only, streams-only,
    or both.
  - `auto` / `network` / `published` connect-modes resolve the upstream address
    per container, so it works whether quicgate runs on a bridge network or
    `network_mode: host`.
  - Manual hosts always win a naming conflict; derived routes are never
    persisted (re-derived from live containers). A **Docker** page shows every
    container with the exact reason it is or isn't routed, plus one-click
    **Convert to host** to graduate a container to editable configuration.
  - Read-only Docker client over the socket (list / inspect / events), no
    third-party SDK, zero new dependencies.

[1.2.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.2.0

## [1.1.1] - 2026-07-23

### Added
- In-app **Help & FAQ** page (the `?` icon in the top bar): common recipes and
  concepts (access-list evaluation, the GET-from-everywhere pattern, hosts vs
  streams, certs/HTTP-3, admin-port safety, API tokens). Embedded, works offline.

[1.1.1]: https://github.com/Quicgate/quicgate/releases/tag/v1.1.1

## [1.1.0] - 2026-07-23

### Added
- **Streams can reuse an access list as their source filter** instead of
  retyping CIDRs — pick an access list on the stream, and its allow CIDR/host
  rules become the source allowlist (only IP rules apply at L4).

### Changed
- Method-scoped access rules now use clickable **HTTP-verb chips** in the UI
  instead of a free-text box (keyboard-accessible; none selected = all verbs).

[1.1.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.1.0

## [1.0.0] - 2026-07-23

First public release. quicgate is a single-binary reverse-proxy manager: the
Nginx Proxy Manager workflow on a native Go engine (HTTP/1.1/2/3), automatic
Let's Encrypt certificates, and every advanced option as a typed, validated
setting instead of a free-text config blob. It has been running a ~50-host
homelab in production.

### Hosts & TLS
- Proxy, redirection (301/302/307/308), 404 and static-file hosts; wildcard
  domains; load-balanced upstream pools with active health checks; custom
  locations (path prefix → upstream) and path rewrites.
- Automatic Let's Encrypt (HTTP-01), DNS-01 wildcards, custom cert upload,
  self-signed generation, custom ACME CAs, mTLS client certs, per-host minimum
  TLS version, HSTS, hardened AEAD-only cipher defaults, HTTP/3 with a per-host
  opt-out that clears the browser's cached Alt-Svc hint.

### Security & access
- Access lists: ordered CIDR / dynamic-DNS / GeoIP-country rules **plus
  per-rule HTTP-method scoping**, basic auth, satisfy any/all.
- CORS preflight requests bypass the auth gate (the real request stays gated).
- Forward-auth (Authelia/Authentik/Keycloak), per-IP rate limiting,
  block-common-exploits, bad-bot blocking, fail2ban-style auto-ban.
- Admin hardening: strict CSP, same-origin CSRF guard (bearer-exempt),
  server-side forced first-password change, `SameSite=Strict`/`Secure`/
  `HttpOnly` cookies, TOTP 2FA, API tokens, optional OIDC and LDAP login.

### Streams & router
- TCP/UDP L4 forwards with source whitelists, PROXY protocol v1/v2, TLS
  termination, SNI passthrough routing, port ranges.
- Router port-forward management over UPnP IGD (self-healing after reboots).

### Ops
- JSON access logs with a built-in per-host and system-wide viewer, Prometheus
  `/metrics` (behind auth, per-host), one-click backup/restore, declarative
  JSON import, effective-config viewer, certificate renewal alerts.
- Runs fully offline: fonts and Swagger UI are vendored, no runtime CDN calls.
- Version is stamped into the binary and shown in the UI (`/api/version`).

[1.0.0]: https://github.com/Quicgate/quicgate/releases/tag/v1.0.0
