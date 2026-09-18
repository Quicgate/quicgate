# quicgate WireGuard integration: design spec

Status: **v3, revised after two design reviews. Release A (secrets at rest in 1.15.0, WireGuard
sites in 1.16.0) is built; Releases B and C are not.** What Release A left for later is listed
at the end of section 15.
Date: 2026-09-18. Applies on top of quicgate v1.14.x.

This spec reverses a stated non-goal ("tunnelling to networks quicgate cannot reach directly",
FEATURES.md). Security decisions are numbered **S1..S54** (S15, S25 and S32 are retired, replaced by S47, S45
and S48). Numbers keep their meaning across versions; text marked *(v2)* or *(v3)* changed in
that revision. Section 16 records what the review found
and what was done with each point.

Wording rule for this document and for the product: the feature gives an **authorization lease
that is renewed on positive evidence**. It never claims that "the user's SSO session is verified",
because no relying party can know that for every provider (S45).

## 1. Summary

Three features on one embedded, userspace WireGuard endpoint:

| Part | Name | What it does | Who may create peers |
|---|---|---|---|
| 1 | Site tunnels | An upstream or stream target can be reached "via site X", where X is a plain WireGuard peer (a router, a Linux box, a VPS). Also covers quicgate on a VPS with the home network dialling out. | admin |
| 2 | Private entrance | Phones and laptops connect and reach quicgate's own hosts inside the tunnel, with the real hostnames and certificates. Access lists gain VPN rules. Hosts can be VPN-only. | admin |
| 3 | LAN access | A connected device can reach LAN addresses (TCP and UDP) that a policy grants to the groups of its owner. **Single sign-on is mandatory**: devices are enrolled through an OIDC-gated portal and stay configured only while the owner's authorization lease is renewed. | the user, through the portal (plus one break-glass path, S33) |

## 2. Goals and non-goals

Goals:

- Keep quicgate one static, unprivileged binary in a `FROM scratch` image. No TUN device, no
  `NET_ADMIN`, no kernel module, no iptables, no changes to routing **on quicgate's host**. (A
  remote site's router does need forwarding and return routes or NAT; section 6.)
- Stock WireGuard clients. No quicgate client app.
- Every failure mode closes access. Nothing in this feature may widen what the public listeners
  serve, and nothing may let a VPN user appear to the public listeners or to streams as a trusted
  local address (S48).
- Off by default. With the feature off, no UDP port is open and no code path below runs.

Non-goals (v1, explicitly out):

- Exit node or full tunnel. Split tunnel only. **No promise of leak prevention:** a client's
  other traffic, including IPv6 and queries to other resolvers, bypasses the tunnel by design.
- IPv6 inside the tunnel, in site networks and in policy routes. All three reject IPv6 in v1.
- Site-to-site or peer-to-peer routing through quicgate. Peers never reach each other.
- A login on every connect. Stock WireGuard has no login step (S24).
- Deriving `Remote-User` or any application identity from the VPN identity (S19).
- Kernel-mode WireGuard, mesh, device posture checks, ICMP forwarding to the LAN, multicast and
  broadcast forwarding (mDNS, SSDP, NetBIOS name browsing).
- Forward-auth endpoints, identity providers and ACME reached via a site.
- Providers that issue no refresh token (S45). A weaker interactive-only mode is deferred.
- Protection beyond the first hop: a user granted a route to a LAN proxy, a router or an SSH
  server can do whatever that machine lets them do. Destination checks govern the connection
  quicgate makes, not what the destination does next. Application authentication and network
  controls on the LAN remain necessary, and the docs say so.

## 3. Verified groundwork

A spike built and ran `golang.zx2c4.com/wireguard` (device + `tun/netstack`, gVisor network stack)
as a static `CGO_ENABLED=0` Linux binary under Go 1.27.1, the toolchain of the release image, in a
container without privileges. Size of the standalone spike: 5.8 MB, so roughly +5 MB on the
quicgate image. Dependency risk: wireguard-go pins a specific gVisor commit and gVisor follows Go
releases closely; a Go bump can break the build until upstream moves. CI fails closed on that.

Not yet verified, and therefore acceptance tests rather than assumptions: a keypair generated
with WebCrypto X25519 works in the official WireGuard clients (S21, Release B); the
promiscuous-NIC forwarder on the pinned gVisor commit (S27, Release C). Nothing in the design
depends on an unproven packet lifetime inside the stack (S40).

## 4. Architecture

```
                    UDP :51820 (host socket, the only new listening port)
                          |
                 wireguard-go device  (one interface, one server key)
                          |
                 gVisor netstack (userspace IP stack, no host interface)
                   |              |                     |
        VPN listener       tunnel DNS            flow forwarder (Part 3 only)
     TCP 80/443 on the    UDP/TCP 53 on the    accepts TCP/UDP to any other
     tunnel address       tunnel address       destination, applies policy,
     -> same routing      -> own names only    dials out from the HOST network
        table, flagged       + raw relay
        "arrived via VPN"

  outbound "via site X": engine dialer -> netstack.DialContext -> tunnel -> site peer
```

- New package `internal/wg`. The engine owns one `wg.Manager`, created only when `wg_enabled` is
  on. Its compiled state (peers, policies, sites) is rebuilt on every `Reload`.
- Parts 1 and 2 can use the stock `netstack.Net` (dial and listen only). Part 3 needs quicgate's
  own TUN-to-gVisor glue with a promiscuous NIC and TCP/UDP forwarders. This is the most delicate
  code in the feature (S27 to S31, S49).
- The userspace stack is **not a sandbox**. It shares the process, the heap and the fate of the
  public proxy: a panic in a gVisor goroutine that quicgate does not own ends the process, and
  the container restart policy is the recovery. This is an accepted trade-off of the single
  binary; S49 bounds the memory side and section 14 tests the failure side.

Address plan:

- Tunnel network: one IPv4 prefix, default `10.77.0.0/24`, admin-configurable, /16 to /29.
  quicgate is the first address.
- Every peer gets exactly one /32 from the tunnel network, assigned by the server.
- A site additionally declares its **site networks** (remote IPv4 prefixes).
- Changing the tunnel prefix re-addresses every peer and invalidates every client config. It is a
  separate, confirmed admin action that ends all leases and stops the device first; it is never a
  side effect of a settings save.

## 5. Identity, generations and revocation

**S1.** On the WireGuard device, a peer's AllowedIPs are exactly its /32, plus its site networks
when it is a site. wireguard-go checks the decrypted inner source against the sending peer's
AllowedIPs before handing the packet to the stack; roaming does not change that. Therefore,
inside the netstack, **the source address of a packet identifies the peer** (for a device: one
device; for a site: "some host in that site", never a user). This covers what enters the stack.
It does not by itself cover what is already inside it when configuration changes; S39 to S42 do.

**S39. Immutable peer identity and generations.** Every peer has a `peer_id` that is never reused
and never edited; a changed key is a new peer (S43). The manager keeps, per peer, a small record:
`{peer_id, address, kind, owner, state, authz_generation, mu, flows}`. The global compiled state
has a monotonically increasing `epoch`. `authz_generation` increases whenever anything that
decides what this peer may do changes: its state, its owner's groups, a policy that applies to it,
the site's networks.

**S2 *(v2)*. Admission and revocation are synchronised per peer.** Every admission (a forwarder
flow, a connection accepted on the VPN listener, a DNS query, a `via` dial towards a site) runs
under the peer record's mutex: check `state == active`, evaluate policy at the current
`authz_generation`, register the flow in `flows`, release. Revocation and suspension take the same
mutex: set the state, bump the generation, take the flow set, release, then close every flow in
the set. An admission that loses the race sees the new state and is refused; one that wins is in
the set and gets closed. There is no interval in which a flow is admitted but unregistered. A flow is
registered **before** its outbound dial starts, together with a cancellable context, so a pending
dial is revocable like an established connection. Policy edits bump generations and re-evaluate
the registered flows of affected peers; those no longer allowed are closed.

*(v3)* Admission of an SSO-enrolled device also compares the clock with the owner's deadlines
(S45): `now < access_until` and `now < hard_until`. The stored state alone is never enough, so a
late or stuck expiry worker cannot extend access.

**S42. What revocation closes.** Forwarder flows (TCP and UDP), connections on the VPN listener
including HTTP/2 connections, hijacked WebSocket connections and their upstream halves (the
listener wraps every accepted `net.Conn` and registers it under its peer), pending DNS relays, and
for a site every `via` connection including pooled idle ones (S46). Pending outbound dials are
cancelled through their contexts, and so are the request contexts of HTTP requests in flight on
the VPN listener, which cancels their upstream round trips. *(v3)* Revocation means: **no further
access, and outstanding work cancelled where that is possible.** It cannot recall a request that
an upstream or a LAN service has already received. After the peer is removed from the device
nothing can be encrypted to it, so closing is about side effects and resources, not only replies.

**S41. Applying device configuration.** wireguard-go's `IpcSet` is not transactional. Order of an
apply: (1) under S2, mark removed and suspended peers and close their flows; (2) remove them from
the device; (3) swap the address lookup table; (4) add new and restored peers. If any device call
fails, quicgate re-applies the complete intended configuration with `replace_peers=true`; if that
fails too, it brings the device down, which closes everything (section 12), and reports the
error through the existing reload contract. A half-applied configuration is never left running.
An existing site's AllowedIPs are always written whole (`replace_allowed_ips=true`), never
patched, and only after S40 has decided whether the change needs a reset (S52).

**S40 *(v3)*. An address never changes owner inside a running stack instance.** No argument
from packet lifetimes is made, because none has been proven for the pinned stack, and a
`peer_id` on a registered flow protects that flow only: it says nothing about an old packet that
is still queued and would open a *new* flow after the address has a new owner. So the rule is
structural. The manager keeps, for the life of one netstack instance, the set of every address
and prefix that any peer has owned in it. Within that instance:

- a tunnel /32 that was freed stays unassigned (allocation is monotonic; freed addresses are
  tombstoned in the database with the id of the stack instance that last used them);
- a site may gain a prefix that nobody has owned in this instance; any other change of prefix
  ownership (a prefix removed from a site, moved to another site, narrowed or widened across an
  owned range, a site deleted and its prefix given away) is an **ownership change**.

An ownership change, and an exhausted prefix, are resolved only by a **controlled stack reset**
(S52). A process restart is a reset too, so after a restart every tombstoned address is free.
This applies from Release A, where sites already use the stack.

**S52. Controlled stack reset.** Steps: under S2 mark every peer as closing and close every flow;
bring the WireGuard device down; destroy the netstack instance and wait for its goroutines; create
a fresh instance with a new instance id; apply the complete intended configuration; bring the
device up. During the reset `via` dials fail and the VPN listener is absent; nothing falls back
(S8). Saving a change that needs a reset says so before it is applied ("this interrupts all VPN
traffic for a moment"). The reset is also the last resort of S41.

**S3.** Public keys are unique across all peers of every kind and every state, including revoked
tombstones (database constraint). Registration rejects a key that is already present, the
server's own public key, the all-zero key and any value that is not 32 bytes of base64. Without
this, enrolling a duplicate key would move another peer's AllowedIPs.

**S4.** Site networks may not overlap each other, the tunnel network, loopback, link-local,
multicast or unspecified ranges. Overlap with one of the machine's own interface networks is
allowed only with an explicit confirmation flag, because of S6.

**S5.** Peers never reach each other. IP forwarding between peers is off in the netstack, and the
Part 3 forwarder denies every destination inside the tunnel network and inside any site network.

## 6. Part 1: site tunnels

Data: a site is a peer of kind `site` with a name, public key, preshared key (always, S37), site
networks, optional fixed endpoint (`host:port`, for a site that quicgate dials), and keepalive.

Use: `Upstream`, pool members, custom locations and stream targets gain an optional `via` field
holding a site id.

**S6. No implicit routing.** The tunnel is never consulted by address. A dial goes into the tunnel
if and only if its target carries `via`. A target without `via` always uses the host network, even
when its address lies inside some site's networks.

**S7 *(v2)*. Resolve once, dial the literal.** When `via` is set, a hostname target is resolved
once through the host resolver, every candidate address is checked against the site's networks,
and quicgate dials the **checked IP literal**. The name is never resolved again during connection
set-up. No address inside the site networks: the dial fails. Literals are also validated at save
time.

**S8 *(v2)*. One dialer, no fallback, no handshake precondition.** Today the code dials targets
in five places: the upstream transport (`engine.go`), the health checker (`health.go`, two
places), TCP and UDP streams (`streams.go`). The forward-auth client (`middleware.go`) stays
host-only. All target dials move behind one `dialer` that takes the target including `via`.
A `via` dial is **admitted** when the feature is on, the device is up and the site is configured
and enabled. It is then attempted with the ordinary bounded dial timeout, which lets WireGuard
start its handshake; WireGuard handshakes are driven by traffic, so requiring a recent handshake
before dialling would keep an idle or new tunnel down forever. On timeout or error the dial
**fails** (HTTP 502, stream refused). It never falls back to the host network: a fallback would
send cookies and credentials to whatever local machine owns the same address.

**S9 *(v2)*.** Handshake age (up when younger than 180 s) is **status only**: shown in the UI and
in health, never used to admit or refuse a dial. A site without a fixed endpoint can only be
reached after it has contacted quicgate, so dial-in sites must set `PersistentKeepalive`; the
generated site config sets 25 s. *(found while building)* Such a site also returns late after a quicgate
restart or a controlled reset (S52): it keeps sending on its old session and only shakes hands
again when WireGuard's no-reply timer fires, about 15 s after its next keepalive, so up to about
40 s with a 25 s keepalive, during which `via` upstreams answer 502. A site with a fixed endpoint
is back at once, because quicgate starts the handshake with its first dial. The UI and the docs
recommend an endpoint wherever the site has a reachable address.

**S46. Transports are per site, and die with it.** Today one `http.Transport` serves a host's
primary upstream, its pool and its locations, and Go pools connections by scheme and address. Two
backends with the same address, one local and one via a site (or via two different sites), would
share pooled connections. Therefore: a transport's identity includes `via` (site id and the
site's generation); a host gets one transport per distinct `via` among its backends, each with a
dial function bound to exactly that `via`. On reload, transports of a changed or removed route
call `CloseIdleConnections`; when a site is disabled, removed or re-keyed, or the feature is
switched off, all its connections are closed through S42, in flight included. Streams already
close their connections on change.

**S10.** Traffic arriving *from* a site peer can reach the VPN listener and tunnel DNS (Part 2),
nothing else. Sites never get LAN access.

Documentation duty for Part 1: the remote side needs IP forwarding, firewall rules, and either a
return route to the tunnel address or NAT; with examples for a Linux box, OpenWrt and pfSense.

## 7. Part 2: private entrance

### 7.1 VPN listener

quicgate listens on TCP 80 and 443 on its tunnel address inside the netstack and serves the same
routing table as the public listeners, with the request flagged `viaVPN` and the peer attached to
the request context.

**S11. Bound to the listener, not to an address.** `viaVPN` is set only by the netstack listener.
No check anywhere compares `RemoteAddr` with the tunnel prefix or a site prefix to decide that a
request came through the VPN.

**S12.** The VPN listener never applies trusted-proxy real-IP rewriting and never accepts PROXY
protocol. `X-Forwarded-For` from a peer is handled as from any untrusted client.

**S13.** HTTP/1.1 and HTTP/2 only in v1. Responses on the VPN listener do not advertise `Alt-Svc`.

### 7.2 Access lists on the VPN listener

Today a rule has **exactly one selector** out of `cidr`, `host`, `country` (validated), and an
optional `methods` list that narrows it (selector AND method). `vpn` becomes a fourth selector
with the same rule: exactly one selector per rule, `methods` still ANDs.

**S53 *(v3)*. Subjects are structured and always name their provider.** `vpn` is an object, not a
string: `{"kind":"any"}`, `{"kind":"site"}`, `{"kind":"device"}`, `{"kind":"peer","peer":<id>}`,
`{"kind":"user","provider":<id>,"sub":"..."}`, `{"kind":"group","provider":<id>,"group":"..."}`,
`{"kind":"any-user","provider":<id>}`. A group is only ever compared together with the provider
that asserted it: `admins` from provider 1 never satisfies a rule or policy about `admins` from
provider 2. The same subject type is used in three places: `vpn` access rules, LAN policies
(S26), and the portal's **enrolment subjects**, the list that says who may enrol devices at all.
`any-user` is the single, explicit way to say "every authenticated user of this provider"; an
owner who matches only through `any-user` needs no group.

**S47 *(replaces S15)*. Two listeners, two vocabularies.** For a `viaVPN` request only `vpn`
rules are evaluated; `cidr`, `host` and `country` rules are skipped, allow and deny alike. For a
public request `vpn` rules are skipped. First match wins and no match denies, as today. So an
existing `allow 192.168.0.0/16` or `allow 10.0.0.0/8` never admits a peer, whether the peer's
source is a tunnel address or a site host such as `192.168.1.50`, and enabling the feature cannot
change who passes an existing list. To let peers into a protected host the admin adds an explicit
`vpn` rule. A host without an access list is public and peers reach it too. Basic-auth users and
`satisfy` work unchanged.

**S14.** A `vpn` rule matches only when the peer is `active` at that moment (S2). `user`, `group`
and `any-user` subjects match only SSO-enrolled devices of that provider, against the owner's
groups from the last renewal (S45).
With the feature off, `vpn` rules never match, and a list whose only allows are `vpn` rules admits
nobody.

**S16.** L4 streams: no `vpn` rules in v1. Stream listeners are host sockets; peers cannot reach
them through the forwarder either (S48).

### 7.3 VPN-only hosts

**S17 *(v2)*.** A host option `vpnOnly` removes the host from the public listeners' view of the
routing table, for HTTP/1.1, HTTP/2 and HTTP/3 alike: a public request for it gets the default
site, identical to an unknown host, also when SNI and `Host` disagree (the existing 421 rule for
mTLS hosts is the model), and the public `GetCertificate` declines its names unless another,
public host shares the certificate (a wildcard). Switching `vpnOnly` on closes the host's
existing public connections. If the feature is off or the device failed to start, a `vpnOnly`
host is served nowhere. It needs a DNS-01 or custom certificate; the UI says so. This hides the
**application**, not the **name**: certificate transparency logs and DNS can still reveal that the
hostname exists, and the docs say so.

### 7.4 Auto-ban, rate limits, identity headers

**S18.** Refusals on the VPN listener are logged with the peer, count toward rate limits, and do
not count toward auto-ban.

**S19.** No identity header (`Remote-User`, `Remote-Email`, `Remote-Groups`) is ever derived from
the VPN identity. Possession of a device key is not a fresh user authentication. A host that wants
the user identity keeps its OIDC gate; the two compose.

### 7.5 Tunnel DNS

UDP and TCP 53 on the tunnel address. Client configs set `DNS = <tunnel address>`.

**S20 *(v2)*.** Only the question is parsed, with `golang.org/x/net/dns/dnsmessage`; no
hand-written parser. For a name that matches a configured host domain (exact or wildcard) quicgate
synthesises the answer: A with the tunnel address (TTL 60) and NODATA for every other type,
including AAAA. Synthesised answers set AA, never AD, and carry no signatures: they must not look
like validated upstream data. Every other query is **relayed as raw bytes** to the host's
resolvers and the reply relayed back unmodified, over the same transport the client used, so EDNS
options, DO and AD flags stay the upstream's and the client's business. No cache. *(v3)* The
boundaries of the relay:

- **Isolation.** Every relayed UDP query gets its **own** connected upstream socket with a random
  source port, bound to exactly one `(peer_id, client port, query id)`. A reply is accepted only
  on that socket, from that resolver, with that id and question, once. Two peers sending the same
  id and question can never receive each other's answers, and no socket is shared.
- **Sizes.** Queries over 512 B (UDP) or 4 KB (TCP) are dropped. Upstream replies are read into a
  full 64 KB buffer so nothing is cut off locally without quicgate knowing. The client's limit is
  512 B, or the EDNS size of its query capped at 1232 B. A reply that fits is relayed untouched.
  A reply that does not fit is **never forwarded cut off**: quicgate answers with a header that
  copies the reply's id and flags and sets **TC**, plus the question, so the client retries over
  TCP, which is relayed the same way (TCP replies up to 64 KB).
- Malformed upstream replies, a timeout (2 s) or an exhausted in-flight table give SERVFAIL.

Limits: see S49. Reachable only inside the tunnel, so not an open resolver. Names of relayed
queries are not logged; counts per peer are.

Suppressing AAAA for own names does not stop a dual-stack client from reaching a public host over
IPv6 outside the tunnel. That is the split tunnel working as designed (section 2), and such a
request is an ordinary public request.

### 7.6 Admin-issued devices

An admin can create device peers for Part 2. The keypair is generated in the admin's browser
(S21); such a device reaches the VPN listener and DNS only, never the LAN (exception: S33).

## 8. Part 3: LAN access with mandatory SSO

### 8.1 Portal

A new host type `vpn-portal`: a domain chosen by the admin, served on the public listeners and the
VPN listener, bound to exactly one identity provider from the existing `oidc_providers` table.

**S21 *(v2)*. Private keys never reach the server.** The portal page generates the X25519 keypair
with WebCrypto, sends only the public key, and assembles the client config and its QR code
locally. That this key material works in the official clients on iOS, Android, Windows, macOS and
Linux is an acceptance test of **Release B**, where admin-issued devices first use it, not an
assumption and not something to discover in Release C. *(v3)* Fallback for browsers without X25519:
the user creates an empty tunnel in the WireGuard app (the app generates the keypair), pastes its
public key into the portal, and the portal shows the values to enter (address, DNS, and the peer
section). The portal cannot produce a complete file in that case and says so. The config and the
preshared key are shown **once**; a lost config means revoking the device and enrolling a new
one. No JavaScript crypto library is vendored for key generation.

**S22. Separate surface.** Portal handlers live in the engine under `/.qg/vpn/` on the portal host
only. They share no session, cookie, token or CSRF state with the admin API on :81, and no admin
route is reachable through the portal host. The portal can do four things: list my devices, add a
device, revoke my device, log in again. Every object id in a request is checked against the owner
in the server-side session. Per-user and per-address rate limits apply. Limits: 5 devices per user
(configurable), device name at most 64 printable characters.

**S51. Portal cookies and CSRF.** Two cookies. (1) A short-lived OIDC transaction cookie
(`SameSite=Lax`, 10 minutes, signed, purpose-bound like the existing state cookie) carrying state,
nonce and the PKCE verifier; the callback checks `state` against it and consumes it. (2) The
portal session cookie: host-only (no `Domain`), `HttpOnly`, `Secure`, `SameSite=Strict`, an
opaque random id for a server-side session, **rotated at every login**. State-changing calls
additionally require an `Origin` header equal to the portal origin exactly, and a JSON content
type. `SameSite` is defence in depth, not the CSRF control.

**S23. Identity key.** The owner of a device is `(provider id, sub)`. Email is display only.
Deleting a provider, or changing its issuer, is refused while it owns sessions.

### 8.2 What "mandatory SSO" means (S24 *(v2)*)

1. A device can only be enrolled by a user who just completed a **fresh** OIDC login (S54; PKCE,
   nonce, ID-token signature, issuer and audience checks: the existing gate's code path), who
   matches at least one of the portal's enrolment subjects (S53), and whose provider returned a
   refresh token.
2. A device is configured on the WireGuard interface **only while its owner holds an unexpired
   authorization lease**. Outside that, the peer does not exist on the device.
3. A lease is renewed only on positive evidence from the provider (S45). What that evidence
   proves depends on the provider and is documented per qualified provider. quicgate does not
   claim to know that the browser SSO session still exists.
4. *(v3)* Possession of the device key is the credential, and the lease does **not** bound a
   thief's access: while the legitimate owner's lease keeps renewing, a stolen device or a copied
   config keeps working, until the device is revoked or the hard limit passes. The ten-minute
   lease bounds how long a *disabled account* keeps access, nothing else. To make theft visible,
   the portal and the admin UI show each device's last handshake time and last endpoint address.
   The UI and the docs say all of this.

### 8.3 Leases and verification profiles (S45, replaces S25)

Unlike the existing host gate (a stateless signed cookie, no tokens kept), the portal keeps a
server-side session per `(provider, sub)`: the refresh token (sealed, section 9), the groups from
the last renewal, `lease_until`, `login_at`, `generation`, `state`.

- **Lease and deadlines *(v3)*.** Three absolute times, stored with the session:
  `hard_until = login_at + wg_session_days`, written only by a fresh login (S54);
  `lease_until = renewed_at + wg_lease_minutes` (default 10) and
  `grace_until = lease_until + wg_outage_grace_minutes` (default **0**, maximum 60), both written
  **only by a successful renewal** and both capped at `hard_until`. Failed attempts, retries and
  restarts never move any of them. `access_until` is `lease_until`, or `grace_until` when every
  attempt since the last success failed *transiently* (network error, timeout, 5xx). A definitive
  refusal (`invalid_grant` and equivalents) sets `access_until` to now. Admission compares the
  clock with `access_until` and `hard_until` itself (S2); the expiry worker only tidies up.
- A renewal is attempted when half the lease has passed and retried with backoff until
  `lease_until`, which already rides out a restart of the IdP without any grace.
- **Verification profile**, configured per provider, decides what a renewal must show:
  - `refresh`: the refresh grant succeeds.
  - claims source `id_token`: a refreshed ID token is **required**; it is validated (signature,
    issuer, audience, `sub` equal to the stored `sub`) and groups come from it. OIDC makes the ID
    token optional in a refresh response, so a provider that omits it fails this profile.
  - claims source `userinfo`: after the refresh, quicgate calls the provider's UserInfo endpoint
    (from discovery, same issuer) with the new access token; `sub` must equal the stored `sub`
    exactly; groups come from that response.
  - In both cases a missing groups claim means **the empty group set**, never a failure by
    itself: every `group` subject stops matching, `any-user` subjects keep matching. An owner who
    no longer matches any enrolment subject is suspended. *(v3)*
- **What is promised.** For a provider qualified in FEATURES.md the docs state how fast a disabled
  account or a removed group stops renewals (for Keycloak this is to be measured in Release C).
  For any other provider the promise is only: no renewal without a successful refresh grant and
  fresh claims, and access ends at `wg_session_days` at the latest.
- **No refresh token, no enrolment.** The 24-hour fallback of v1 is removed.
- **Hard limit.** `wg_session_days` (default 30, maximum 90) after `login_at` a fresh login at
  the portal is required. The portal shows that date.
- **S54 *(v3)*. A portal login must be a fresh authentication.** Completing an OIDC redirect
  proves little when the IdP silently reuses an existing browser session. Every portal login
  sends `max_age=<wg_auth_max_age>` (default 900 s) and then **requires** an `auth_time` claim in
  the validated ID token that is no older than that plus 60 s of skew. A provider that omits
  `auth_time` fails the login (it is a documented requirement of a qualified provider). Enrolment,
  restoring a lapsed session and resetting `hard_until` all rest on this.
- **Recovery after suspension.** A suspended device has a dead tunnel whose DNS points into it,
  so on many clients nothing resolves until the tunnel is switched off. Procedure, shown in the
  portal and the docs: switch the tunnel off, open the portal, log in, switch it on; the same
  config works again. Keeping suspended peers on the device in a captive state was considered and
  rejected: it would weaken S24(2). Acceptance test: the portal is reachable and usable from a
  client in exactly this state.

### 8.4 States, concurrency and what a login may restore

**S43. States.**

| Object | State | Set by | A new login restores it? |
|---|---|---|---|
| session | `active` | login, renewal | |
| session | `lapsed` | lease ended, hard limit | yes |
| session | `ended` | user logout, admin "end session" | yes |
| owner | `blocked` | admin | **no**; only an admin unblocks. Login succeeds but enrols and restores nothing, and says so. |
| device | `active` / `suspended` | derived from its session; never stored | follows the session |
| device | `revoked` | user or admin | **never**. Terminal. The row stays as a tombstone so the key cannot be registered again (S3). |
| device | `expired` | break-glass expiry | never; a new one must be issued |

A changed key is never an edit: it is a revoke plus a new enrolment with a new `peer_id` (S39).

**S44. Refresh concurrency.** At most one renewal runs per session (per-session mutex). The
renewal reads the session `generation` first and commits with a compare-and-swap
(`UPDATE ... WHERE id = ? AND generation = ? AND state = 'active'`). Ending, blocking, revoking
and logging in bump the generation. A renewal that finishes after an admin ended the session
finds the generation changed, discards its result and the new refresh token, and cannot bring the
session back. Rotating refresh tokens: the new token is sealed and stored in the same commit as
the lease; if quicgate dies between the provider's rotation and that commit, the stored token is
stale, the next renewal is refused, and the session lapses until the user logs in again. That is
the fail-closed outcome and is accepted; a provider's reuse detection revoking the token family
has the same result.

### 8.5 Policy (S26 *(v2)*)

`vpn_policies`: name, a subject of kind `group` or `any-user` (S53, so always with its provider),
and routes. A route is an IPv4 CIDR, a protocol (`tcp`, `udp`, `any`) and ports.

- Default deny. A flow is allowed when any policy whose subject the owner currently matches has a
  route that matches destination, protocol and port.
- Routes must lie within RFC 1918 or RFC 6598 space. IPv6 routes and public address space are
  refused in v1.
- CIDR only, no hostnames.
- The client's AllowedIPs are a convenience. Enforcement is server-side only.

### 8.6 Flow forwarder (S27 to S31)

**S27.** The NIC is promiscuous so the netstack accepts packets for any destination. A TCP
forwarder and a UDP forwarder receive every flow not addressed to the tunnel address itself.

**S28 *(v2)*. Order of checks for a new flow,** on the normalised destination (IPv4 only;
IPv4-mapped forms unmapped; port 0 refused), all under S2:

1. source maps to an `active` SSO-enrolled device or a break-glass device, else drop;
2. never routable: loopback, link-local (includes 169.254.169.254), multicast, the limited
   broadcast address, unspecified, the tunnel prefix, every site network, every entry of
   `wg_protected_endpoints` (S48), and *(v3)* the directed broadcast and network addresses of the
   **subnets actually configured on this machine's interfaces**, for prefixes of /30 and shorter
   only. A policy range is an authorization, not a subnet: it is never used to compute a
   broadcast address, so a /32 grant stays a grant of exactly that host, and both addresses of a
   /31 (RFC 3021) are ordinary hosts. Broadcast addresses of remote subnets are unknowable here
   and left to the routers in between;
3. this machine's own addresses: denied unless S48 allows the exact address and port;
4. policy (S26).

For TCP the check happens before the handshake completes: a denied flow is reset, never accepted
and then closed.

**S48 *(replaces S32)*. quicgate's own listeners are never reachable through the forwarder.** An
allowed flow leaves quicgate from one of the machine's own addresses. If it could reach quicgate's
public listeners or a stream listener, the request would arrive from a local address and pass
CIDR allow rules such as `192.168.178.0/24`, and since v1.14 it would also be exempt from
auto-ban: a trusted-local-source bypass of every access list. Therefore:

- Destinations that are one of this machine's own addresses are denied by default, whatever CIDR
  a policy grants. Peers reach quicgate's hosts through the VPN listener, which is the path that
  knows who they are.
- A policy may grant an own address only as an explicit /32 with explicit ports (for example SSH
  to the Docker host), and never a port on which quicgate itself listens: 80, 443, the admin
  port, the WireGuard port, every stream port and every port-forward source. This is validated on
  save and re-validated on every reload, because stream ports change.
- *(v3)* **Aliases of every quicgate listener, not only the admin port.** From inside a container
  quicgate cannot see where its listeners are published: the Docker host's LAN address, the
  bridge gateway address, translated ports (`8443->443`, a stream published on another port), a
  NAT rule on the router, another proxy in front. Each of those is the same bypass.
  `wg_protected_endpoints` is the admin-maintained list for them. An entry is an address (then
  the address is treated as one of this machine's own: denied, grantable only as /32 plus ports)
  or `address:port` (always denied, never grantable). It must cover the **public, stream and
  admin listeners alike**.
- With host networking the machine's own addresses are known and the rule above is complete for
  them. With bridge networking they are not. Detection of bridge mode is an **aid, not a
  guarantee**: when it triggers, the container's default gateway is added to the own addresses
  automatically, and LAN access refuses to switch on until the admin has either listed the host
  address(es) or confirmed in so many words that no quicgate listener is published anywhere a
  policy can reach. Host networking is the recommended deployment for Part 3.
- The guarantee is therefore **conditional** and worded so everywhere: a VPN user cannot reach a
  quicgate listener through the forwarder *at any address quicgate knows to be its own or has been
  told about*. An alias nobody declared is outside what quicgate can enforce, like the indirect
  reach of section 2.
- Inherent and documented: every LAN service sees quicgate's address as the source of VPN flows.
  A LAN service that trusts that address by IP is thereby opened to every user granted a route to
  it. Grant by port, not by subnet, where that matters.

**S29.** An allowed flow is dialled from the host network by IP literal with a timeout, never by
name. Limits in S49.

**S30.** Every flow is registered under its peer (S2) and closed by S42.

**S31 *(v3)*. Flow log: no record, no flow.** One JSON line per flow in `vpn-flows.log` (rotated
like the access log): time, peer, owner, destination, protocol, port, verdict. The writer is a
bounded queue and never blocks packets, but the record of an **allowed** flow is part of its
admission: if the record cannot be queued, the flow is refused. So every LAN flow that was
allowed has an admission record, which is the audit property S33 relies on. Per-peer flow-rate
limits (S49) keep one peer from filling the queue for everyone. Records of denied flows and the
closing record with bytes and duration are **best effort**: they may be dropped under pressure,
and the number dropped is a visible counter in the UI and in the metrics.

**S49 *(v3)*. Resource budgets, before admission as well as after.** Policy limits on flows do
nothing for resources consumed earlier, so every layer has its own bound. These are **counted
limits with a target**, not a proven ceiling: the target is that the feature's worst case stays
under `wg_memory_budget_mb` (default 128) and that the public proxy keeps a stated share of its
throughput. Both are **acceptance thresholds measured in the load tests of section 14**. If a
release cannot meet them with counted limits alone, it adds load shedding (suspending the
forwarder, then the VPN listener, when the process nears its memory limit) before it ships.

| Layer | Bound |
|---|---|
| WireGuard device | fixed queue sizes of wireguard-go. Cost model: the server public key is in every client config, so it must be assumed known; anyone who knows it can build valid MAC1 values and make quicgate do Curve25519 work per handshake initiation until wireguard-go's under-load detection switches to cookie replies and its per-source rate limiter engages. That CPU is shared with the public proxy. Flood tests include valid-MAC1 initiations from many sources |
| IP fragments | gVisor reassembly memory high and low watermarks set explicitly, 30 s timeout |
| Half-open TCP at the forwarder | `maxInFlight` of the TCP forwarder, global and per peer |
| Established flows | per peer (default 512) and global; idle timeout; UDP sessions per peer with idle reaping |
| Socket buffers | explicit netstack send and receive buffer sizes per endpoint |
| Dials towards the LAN | rate per peer, concurrent per peer |
| VPN listener | connections per peer and global; existing header and idle timeouts |
| Tunnel DNS | queries per peer per second, in-flight relays global, TCP connections per peer and global, 5 s TCP idle, 2 s upstream timeout |
| Flow log | bounded queue, drop and count |

Goroutines that quicgate owns in this package recover from panics, log, and close the affected
flow. A panic elsewhere in the stack ends the process (section 4).

### 8.7 Break-glass (S33 *(v2)*)

If the identity provider is itself behind quicgate, a broken IdP would lock the operator out of
the VPN needed to fix it. One exception to mandatory SSO: the local admin may create at most two
break-glass devices with a LAN policy attached directly. Creating one requires the admin account
to have TOTP enabled and the request to carry the current password and a TOTP code. **An expiry
is required**; the form offers 30 days by default, and a device without expiry needs a second,
separately worded confirmation. TOTP protects issuance only: a stolen break-glass config works
until someone revokes it. Break-glass devices are listed permanently in the Overview "Attention"
panel with their expiry, and every flow they are allowed has an admission record (S31). The
private key still never touches the server (S21).

## 9. Secrets at rest (Release A, prerequisite for everything else)

Today secrets in SQLite are stored in the clear. The complete inventory, from the code: the
settings `oidc_client_secret`, `acme_dns_config` and `sso_cookie_secret`;
`oidc_providers.client_secret`; `custom_certs.key_pem`; and `users.totp_secret`. (API tokens,
admin passwords and basic-auth passwords are stored as hashes and stay as they are.) A locked
store must never read a TOTP secret as "2FA is off": with the key missing, a login for an account
that has 2FA fails, it does not skip the second factor.
FEATURES.md lists encryption as deferred; FEATURES.md lists encryption as deferred. This
feature adds the server private key, preshared keys and refresh tokens.

**S34 *(v2)*.** Secrets are sealed with XChaCha20-Poly1305 (`golang.org/x/crypto`, already a
dependency), a random nonce per value, a `key_id` prefix, and associated data naming table,
column, row id **and purpose**. A refresh token's associated data also names its provider id and
`sub`, so it cannot be opened as another user's or another provider's token.

**S50 *(v3)*. Migration is mandatory, and the backup claim is exact.** Release A seals **all**
secrets in the database, old and new, in a migration at first start, inside one transaction.
Replacing a value does not remove the old bytes from SQLite's free pages or from the WAL, so the
migration continues: `PRAGMA secure_delete=ON` (kept on from then on), `wal_checkpoint(TRUNCATE)`,
then `VACUUM`, then another truncating checkpoint. Backups are already made with `VACUUM INTO` a
fresh snapshot file, which contains live rows only and no WAL or journal; the spec makes that a
requirement: **an archive never contains a copy of the live database file, its WAL, its
shared-memory file or a journal.** The claim then is: *an archive created after the migration
contains no plaintext secret from the database.* It does **not** cover:

- the certificate tree, where ACME and imported private keys are files, as today;
- archives made **before** the migration, which stay as sensitive as they were;
- remnants below SQLite: filesystem blocks, snapshots, and backups of the volume or the VM.

The test seeds distinctive secret values, migrates, creates an archive, and searches the **raw
bytes** of every file in the extracted archive and of the data directory (database, WAL,
shared-memory file) for them. SQL queries prove nothing here.

**S35.** The 32-byte key comes from `QG_SECRET_KEY_FILE` or `QG_SECRET_KEY`; if neither is set,
quicgate generates `secret.key` (mode 0600) in the data directory and says at startup that this
protects against a leaked database or backup, not a leaked data directory.

**S36 *(v2)*. The key, backups and a missing key.**

- A backup never contains the raw key. The admin may give a passphrase when creating a backup;
  then the archive also carries the key wrapped with a key derived from the passphrase (Argon2id).
  Without a passphrase the UI states what a restore elsewhere will lose: every sealed secret.
- **Ordinary start with the key missing or wrong** while sealed values exist: quicgate keeps the
  sealed data untouched, never generates replacements, and disables exactly what depends on it:
  the VPN stays off, OIDC gates cannot be built and close their paths (existing rule), DNS-01
  issuance pauses. It says so in the log and in the Overview "Attention" panel.
- **Replacing secrets is only ever an explicit admin action** ("reset VPN secrets", re-entering
  a client secret), also after a restore without the key. Nothing is regenerated silently.
- **Downgrade.** A binary older than Release A reads a sealed value as if it were the secret.
  Before rolling back, `quicgate -unseal` rewrites every sealed value as plaintext (it needs the
  key) and says that the database is plaintext again; the next start of a new binary seals again.
- Key rotation: a new key gets a new `key_id`; an admin action re-seals every value; values name
  the key that seals them, so a rotation interrupted half-way is resumable.
- Not prevented, stated plainly: an attacker who can write the database can roll a row back to an
  older valid ciphertext. Someone with that access has other options already.

**S37.** The API never returns the server private key, a preshared key after creation, or a
refresh token. Preshared keys are generated server-side, returned once, and used for every peer.

## 10. Configuration, API and UI

Settings (live, applied on reload): `wg_enabled`, `wg_port` (default 51820), `wg_endpoint`,
`wg_lan_access` (Part 3 switch), `wg_lease_minutes`, `wg_outage_grace_minutes`,
`wg_session_days`, `wg_auth_max_age`, `wg_devices_per_user`, `wg_protected_endpoints`,
`wg_memory_budget_mb`.
The tunnel prefix is not a setting (section 4).

- **S38.** `wg_port` joins the engine's reserved ports for streams. With UPnP on, the UDP port is
  mapped like 80/443. With `wg_enabled` off the socket is closed and the mapping removed.
- Admin API: `/api/wg/status`, `/api/wg/peers` (CRUD for sites and admin-issued devices; SSO
  devices are read and revoke only), `/api/wg/policies`, `/api/wg/sessions` (list, end),
  `/api/wg/owners/{id}/block`, `/api/wg/rotate-key`, `/api/wg/renumber`, `/api/wg/reset-stack`. All behind the existing
  admin auth and CSRF guard.
- Backup and declarative import cover sites, policies and portal settings. Import never creates
  SSO devices or sessions, and follows the existing rule that an import may not remove protection.
- UI: a "VPN" page (status, sites, devices with handshake age and traffic, sessions with lease and
  hard-limit dates, policies), `via` on upstream editors, `vpn` rules in the access-list editor,
  `vpnOnly` on hosts, per-peer series in the Overview (bounded by peer count; metric labels use
  peer ids, not names).

## 11. Threat model

Assets: the LAN behind quicgate; services behind access lists; site networks; the server private
key, preshared keys, refresh tokens; the confidentiality of requests sent to upstreams; the
availability of the public proxy.

Actors: (A) internet attacker without keys; (B) enrolled user acting outside their policy;
(C) holder of a stolen device or leaked client config; (D) a compromised or malicious site peer;
(E) a former user, disabled at the IdP; (F) attacker with a leaked database or backup; (G) a
compromised identity provider (out of scope: it can mint any user, as for the existing SSO gate).

| # | Threat | Actor | Mitigation |
|---|---|---|---|
| T1 | Packet or handshake flood on the UDP port | A | WireGuard's MAC1/cookie mechanism; S49 |
| T2 | Spoofing another peer's address inside the tunnel | B, D | S1, S3 |
| T3 | Enrolling a duplicate or revoked public key | B | S3, S43 |
| T4 | Site declares a network to capture local traffic | D, admin error | S4, S6, S7 |
| T5 | Request for a remote upstream sent to a local machine, by fallback or by a reused connection | fault | S8, S46 |
| T6 | Reaching VPN-gated hosts from the public side by forging an address or header | A | S11, S12, S14 |
| T7 | Existing CIDR allow admits peers or site hosts | admin error | S47 |
| T8 | VPN-only host exposed publicly by a fault, HTTP/3, SNI tricks or a disabled feature | fault, A | S17 |
| T9 | VPN identity accepted as application login | design error | S19 |
| T10 | Tunnel DNS abused, or synthesised answers taken for validated data | B, D | S20, S49 |
| T11 | Portal: CSRF, IDOR, session fixation, enrolment by a user without VPN rights | A, B | S22, S23, S24(1), S51 |
| T12 | Former user keeps access | E | S45: bounded by the lease for qualified providers, by `wg_session_days` at worst; deadlines checked at admission (S2); admin end and block |
| T13 | Stolen device or copied config. **Not bounded by the lease** while the owner's lease renews | C | S24(4): revoke, hard limit, last handshake and endpoint shown, admission records (S31) |
| T14 | Reaching loopback, metadata, other peers, the internet or quicgate's own listeners through the forwarder | B, C | S5, S26, S28, S48 |
| T15 | Flows and pending dials surviving revocation; a queued packet opening a flow under a newer owner of its address; half-applied device config | B, D, E, fault | S2, S39 to S42, S40 and S52 (no ownership change inside a stack instance) |
| T16 | Resource exhaustion before or after admission, starving the public proxy | A, B, C, D | S49 |
| T17 | Leaked database or backup yields keys and refresh tokens | F | S34 to S37, S50 |
| T18 | Server key or a private key exposed through the API or logs | A, F | S21, S37 |
| T19 | IdP outage used to keep a disabled user connected | E | S45: grace is zero by default and never applies to a definitive refusal |
| T20 | Break-glass key leak | C | S33 |
| T21 | VPN user passes access lists or auto-ban as a trusted local address via the forwarder | B, C | S48, complete only for addresses quicgate knows or was told about |
| T22 | Ended or blocked session resurrected by a concurrent renewal; revoked device restored by a login | E, B | S43, S44 |
| T23 | Same-address backends share pooled connections across sites | fault | S46 |
| T24 | Any quicgate listener (public, stream, admin) reachable under an address or port quicgate cannot see (bridge mode, published or translated ports, NAT) | B, C | S48 `wg_protected_endpoints`, bridge gate; residual risk is an undeclared alias |
| T25 | Missing key at start silently replaced, destroying or exposing secrets | fault | S36 |
| T26 | Same group name from two providers satisfies one rule | admin error | S53 |
| T27 | Silent IdP session reuse passes as a fresh login for enrolment or for resetting the hard limit | C, E | S54 |
| T28 | Old plaintext secrets survive sealing in free pages or the WAL and leak through an archive | F | S50 |
| T29 | One peer receives another peer's DNS answer; cut-off reply forwarded as if complete | B, D | S20 |
| T30 | CPU exhaustion by valid-MAC1 handshake initiations from anyone who knows the server public key | A, E | S49 cost model, wireguard-go under-load cookies and rate limiter, flood test |

## 12. Fail-closed rules (summary)

1. Feature off or device down: no UDP socket, `via` dials fail, `vpn` rules never match,
   `vpnOnly` hosts are served nowhere, the portal cannot enrol, every registered flow is closed.
2. Compiled state cannot be built: the previous state stays, the reload reports the error,
   nothing is widened. Device apply fails twice: device down (S41).
3. Unknown source address inside the netstack: dropped.
4. Lease not renewed, groups claim missing, claims source unavailable, provider gone: suspended.
5. Policy lookup error or ambiguity: flow denied.
6. Secret key missing or wrong: sealed data preserved, dependent features off, nothing
   regenerated (S36).

## 13. Questions that remain open after the review

- **Q1.** *(closed in v3)* Address reuse no longer depends on packet lifetimes (S40, S52).
- **Q2.** Should admin-issued devices (Part 2) also expire by default?
- **Q3.** *(narrowed in v3)* Whether counted bounds meet the S49 thresholds is decided by
  measurement per release; load shedding is the prescribed answer if they do not.
- **Q4.** *(closed 2026-09-18 by a spike)* Destroying and recreating the stack in one process
  releases everything that matters: 300 cycles, each building a server and a client device with
  their netstacks, moving 256 KB through the tunnel and abandoning a second connection half
  open, then closing both devices (600 stack instances in total) on Go 1.27.1 in an unprivileged
  container: **0 goroutines leaked**, heap in use 1.0 MB at start, 4.0 / 5.0 / 4.6 MB after 100 /
  200 / 300 cycles and 3.8 MB at the end, so a plateau, not growth. S52 can reset in process. The
  spike becomes a regression test in Release A, because a gVisor bump could change this.

## 14. Test plan

Every item gets a failing-first test and a mutation check, as for v1.9.0. **Each rejection test
is paired with the matching success test**, so a feature that refuses everything cannot pass.

- Cryptokey identity with two real wireguard-go devices over loopback UDP: a peer sending from
  another peer's address or outside its site networks is dropped; the legitimate one passes.
- Idle-tunnel recovery: a `via` request to a site with no handshake yet, and after 10 idle
  minutes, succeeds (S8, S9); with the site absent it fails within the dial timeout and the host
  network sees no packet (S8).
- `via` change with a pooled keep-alive connection: after switching a backend from local to a
  site, from site X to site Y, and after removing the site, the next request never uses the old
  connection (S46); two backends with the same address and different `via` never share one.
- Resolve-once: a name that resolves inside the site networks first and outside them on a second
  lookup still dials the checked literal (S7).
- Subjects: `admins` from provider 1 never satisfies a rule or a policy about `admins` from
  provider 2; an `any-user` owner with no groups claim stays active and matches only `any-user`
  subjects; an owner who stops matching every enrolment subject is suspended (S53).
- Access lists: a public request with a tunnel-prefix or site-prefix address, with and without
  trusted proxies, never matches a `vpn` rule (S11); a peer at a tunnel address and a site host at
  `192.168.1.50` never match `allow 192.168.0.0/16` or `allow 10.0.0.0/8` (S47); with an explicit
  `vpn` rule both get in; methods still narrow.
- `vpnOnly`: default-site response and no certificate over HTTP/1.1, HTTP/2 and HTTP/3, with SNI
  and Host mismatched, with a wildcard certificate shared with a public host, with the feature
  on, off and failed; existing public connections close when the option is switched on (S17).
- Revocation races (race detector, Linux CI): admission concurrent with revoke, for forwarder
  flows, VPN-listener HTTP/2 and WebSocket connections and DNS relays; nothing survives (S2,
  S42), including pending dials and in-flight HTTP requests, whose contexts are cancelled.
  Address ownership: within one stack instance a freed /32 is never handed out again and a site
  prefix never changes owner without a reset; moving a prefix from site X to site Y with traffic
  queued from X never yields a flow attributed to Y; after a reset and after a restart the
  addresses are usable again (S40, S52). A failing device apply ends in full replace, reset or
  device down (S41).
- Sessions: `invalid_grant` suspends at once; transient failures suspend at lease end with grace
  0 and later with grace set; retries and a process restart never move `lease_until`,
  `grace_until` or `hard_until`; grace never passes `hard_until`; with the expiry worker stopped,
  admission still refuses after the deadline; a restart of the IdP shorter than half a lease
  suspends nobody; a login answered from an existing IdP session without a recent `auth_time`, or
  without the claim, is refused (S54);
  `sub` mismatch ends the session; missing ID token fails the `id_token` profile; UserInfo with
  another `sub` is refused; missing groups suspends; rotated tokens are stored; hard limit
  enforced; no refresh token refuses enrolment (S45).
- Refresh versus admin: end, block and revoke during an in-flight renewal; the renewal's commit
  is discarded (S44). A login never restores a revoked device, never unblocks an owner (S43).
- Portal: CSRF with and without `Origin`, cross-owner ids, enrolment without a matching group,
  device limit, rate limits, session id rotates at login, transaction cookie single use (S22,
  S51). Recovery: a client with a suspended device and the tunnel switched off reaches the portal
  and restores access without a new config (S45).
- Real clients (Release B): a WebCrypto-generated config connects from the official apps on the
  five platforms; the pasted-public-key fallback connects (S21).
- Forwarder: every entry of the never-routable list, own addresses by default, own /32 with a
  granted port, own /32 with a quicgate listener port (refused at save and after a stream is
  added later), `wg_protected_endpoints`, other peers, public addresses, mapped forms, port 0,
  route boundaries; a /32 grant reaches its host even when that address is the last of a policy
  range; both addresses of a /31 work; the directed broadcast of a real interface subnet is
  refused; TCP denial resets before accept. With every alias declared, a VPN user cannot produce
  a request on a public, stream or admin listener from a local address (S28, S48).
- Containers and NAT: in bridge networking with the public, a stream and the admin listener
  published on translated ports of the Docker host, each is unreachable through the forwarder
  once declared, the gateway address is denied without being declared, and LAN access refuses to
  switch on until the aliases are listed or waived.
- Flow log: with the queue full an allowed flow is refused, not admitted unrecorded; dropped
  best-effort records show up in the counter (S31).
- DNS: two peers sending the same id and question at the same time each get only their own
  answer; an upstream reply larger than the client's limit comes back as TC and the TCP retry
  succeeds; a reply is never forwarded cut off; a reply from another address or on another socket
  is ignored (S20).
- Load and failure: fragment floods, half-open floods, flow and DNS floods from a peer, and
  handshake floods from outside **with valid MAC1** from many sources, while a public-proxy
  benchmark runs next to them; the measured thresholds of S49 (memory, the proxy's share of
  throughput and CPU) are recorded in BENCHMARKS.md and gate the release. An injected panic
  in an owned goroutine closes one flow, not the process.
- Sealing: a ciphertext moved to another row, column, purpose, provider or subject fails to open;
  migration seals every existing secret; a raw-byte search of the extracted archive and of the
  data directory finds none of the seeded secrets and no raw key (S50); passphrase-wrapped key restores; missing and wrong key preserve data and regenerate
  nothing; interrupted rotation resumes (S34 to S36, S50).

## 15. Phasing

1. **Release A:** sealing with mandatory migration and the raw-byte test (section 9), WireGuard
   device, sites, the `via` dialer, per-site transports, address ownership and the controlled
   reset (S40, S52). Flag `wg_enabled`.
2. **Release B:** VPN listener, tunnel DNS, `vpn` rules with structured subjects, `vpnOnly`,
   admin-issued devices, and the real-client key test (S21).
3. **Release C:** portal, leases, policies, forwarder, break-glass. Flag `wg_lan_access`, marked
   experimental in FEATURES.md until an external review of the built code has been done and
   Keycloak has been qualified live for S45.

Each release gets its own adversarial review of the code, separate from this design review.

**Release A as built (1.15.0 and 1.16.0), and what it left open:**

- Built: sealing with mandatory migration and the raw-byte test (S34, S35, S50, the downgrade
  command); the device, sites, `via` on upstreams, pools, locations and streams; one dialer with
  no fallback (S6 to S8); per-site transports and closing of replaced routes' idle connections
  (S46); address ownership and the controlled reset (S40, S52) with the no-leak regression test;
  site validation (S3, S4); keys made in the browser and the configuration shown once (S21, S37).
- Found while building and added: an endpoint name that does not resolve affects only its site,
  and names are looked up again every five minutes; a dial-in site returns up to 40 s after a
  restart (S9).
- Within one host an address may be reached one way only. The spec allowed the same address
  through different sites in one pool; the store refuses it, which keeps the balancer, the health
  keys and the pools simple. It can be lifted later if someone needs it.
- Not built yet from section 9: the passphrase-wrapped key in backups (S36) and a key-rotation
  action (rotation works by editing the key file). The docs say to keep the key with the backups.
- Not built yet from S42: cancelling the request contexts of HTTP requests in flight through a
  site when it is removed. Their connections are closed, which ends them, but through the
  transport's error path rather than a cancelled context.
- S49 resource budgets apply to Parts 2 and 3 (inbound traffic). Release A only dials out; its
  only new inbound surface is the WireGuard UDP port.

**Releases B and C as built (1.17.0), and what they left open:**

- Built: the tunnel listener for HTTP, TLS and DNS, bound to the listener and never to an
  address (S10 to S13, S20); `vpnOnly` with the same public answer as an unknown name (S17);
  structured VPN subjects as the fourth selector, never mixed with address rules (S14, S47,
  S53); devices with terminal revocation (S39, S43); the portal as a separate surface with
  PKCE, nonce, strict cookies and origin checks, a fresh login and a required refresh token
  (S21 to S23, S51, S54); leases with generation compare-and-swap, transient versus definitive
  failures, grace and hard limit (S44, S45); policies and the forwarder with the check order,
  "no record, no flow" and the protection of quicgate's own listeners (S27 to S31, S48);
  break-glass devices.
- Found while building and changed: freed tunnel addresses are tombstoned without an instance
  id and stay out of use until the network is exhausted, which is stricter than S40 asks (a
  restart does not free them) and needs no bookkeeping. A reused address still forces a reset.
  Keepalives to a dial-in peer start when it has been heard from. Dial-in peers are called back
  at their last authenticated address after a restart, which closes the 40 s gap noted above.
  An identity provider cannot be deleted while a policy, a portal, a VPN rule or a live device
  names it.
- Not built: the real-client key test of S21 against the official mobile apps (browser keys are
  verified against the embedded implementation instead); load and flood tests for S49 (the
  budgets are fixed constants); S36 and S42 as above; live qualification of Keycloak for S45.
- The external review of the built code, which section 15 makes the condition for dropping the
  "experimental" mark from LAN access, has not happened yet.


## 16. Review record (2026-09-18, design only)

Everything below is **addressed in the revised design, pending implementation verification**.
None of it is a verified defect in built code, and none of it counts as fixed until the tests of
section 14 exist and pass.

### Round 1 (on v1)

Verdict: revise before implementation. All ten findings were accepted, two with a different
remedy than proposed. Round 2 judged findings 2 (address reuse) and 7 (aliases) only partially
addressed in v2; see below.

| # | Finding | Disposition |
|---|---|---|
| 1 | S8 required a handshake that only a dial can cause: deadlock for new and idle tunnels | Accepted as proposed: S8, S9 |
| 2 | 10-minute quarantine proves nothing; revocation must cover queued traffic, VPN HTTP connections, WebSockets, DNS, partial device failures | Accepted: S2, S39 to S42; the prefix change became a separate action |
| 3 | "SSO session verified" overstates what a refresh proves; ID token optional on refresh; 24 h fallback contradicts the model; default to suspension | Accepted: lease wording, S45 profiles, fallback removed. Grace default is 0, with renewal at half lease and retries so an IdP restart does not drop everyone |
| 4 | A renewal can resurrect an ended session; "login restores" could restore revoked devices | Accepted as proposed: S43, S44 |
| 5 | Connection reuse defeats per-dial site selection; resolve-then-resolve-again | Accepted, and found to be worse in the code than stated: one transport per host is shared by all its backends, so same-address backends would share connections across sites. S46, S7 |
| 6 | Site hosts have site-LAN sources, so S15's warning missed them; AND/OR of selectors undefined | Accepted with a different remedy: instead of warning about overlaps, the VPN listener evaluates only `vpn` rules (S47), which removes the class. Selector semantics stated in 7.2 |
| 7 | Admin port under other addresses; indirect reach; forwarder as trusted-local-source bypass | Accepted: S48 (own listeners never reachable, protected endpoints, bridge-mode gate). Indirect reach through LAN machines is declared a non-goal in section 2 |
| 8 | "Migration recommended" contradicts "no plaintext in backups"; missing key must not replace secrets | Accepted: S50, S36, S34. Added a passphrase-wrapped key in backups so a restore elsewhere does not lose every client secret |
| 9 | IPv6 out of scope yet ULA routes allowed; DNS details; leak promise; recovery after suspension | Accepted: IPv6 refused everywhere in v1; DNS became parse-the-question plus raw relay (S20), which hands truncation, EDNS and DNSSEC flags to the upstream instead of re-implementing them; captive recovery rejected in favour of a documented tunnel-off procedure with an acceptance test |
| 10 | Resources consumed before admission; shared fate with the proxy | Accepted: S49, section 4, load and failure tests |
| Q5, Q8, S21, Part 1 docs, S17 | cookie split and exact Origin; break-glass expiry; fallback cannot build a full config; remote-side routing; HTTP/3 and wildcard cases | Accepted: S51, S33, S21, section 6, S17 |

### Round 2 (on v2)

Verdict: a focused v3 before implementation. All seven findings and five corrections accepted.

| # | Finding | Disposition in v3 |
|---|---|---|
| 1 | 120 s is the same unproven lifetime argument as 10 minutes; a `peer_id` on a flow does not cover a queued packet that opens a new flow; site prefixes change owner too; needed in Release A | S40 rewritten: no address or prefix changes owner inside a running stack instance; ownership changes and exhaustion need a controlled stack reset (S52); S41 writes AllowedIPs whole. Moved into Release A. Q1 closed, Q4 opened (does a destroyed stack release everything) |
| 2 | Published public and stream listeners are the same bypass as the admin port; bridge detection is no guarantee; the absolute claim is too strong | S48: aliases of every listener, address or address:port entries, gateway denied automatically, gate on declaring or waiving, host networking recommended, the guarantee worded as conditional; T21, T24 |
| 3 | Admission must check the deadlines; grace anchored to the last success; a redirect is not a fresh login; the lease does not bound a thief | S2 deadline check, S45 three fixed deadlines, S54 `max_age` plus required `auth_time`, S24(4) and T13 corrected |
| 4 | `group:<name>` is not provider-qualified; "every authenticated user" inconsistent with the group requirements | S53 structured subjects with provider, `any-user`, enrolment subjects; a missing groups claim is the empty set, not a failure |
| 5 | Sealing rows does not remove plaintext from free pages and the WAL | S50: secure_delete, truncating checkpoints, VACUUM; archives only from `VACUUM INTO` snapshots (already how backups work today); raw-byte test; limits of the claim stated |
| 6 | A local cut-off is not DNS truncation; identical ids from two peers on a shared socket | S20: one upstream socket per query, 64 KB read buffer, quicgate sets TC itself, never forwards a cut-off reply |
| 7 | Directed broadcast computed from a policy range breaks /32 grants and /31 links | S28: policy ranges never define broadcast; only real interface subnets of /30 and shorter |
| c1 | "One MAC check" understates the cost: the server public key is known to every client | S49 cost model, T30, valid-MAC1 flood test |
| c2 | Counted limits do not prove a 128 MB ceiling | S49: targets verified by measurement, load shedding prescribed if missed |
| c3 | Pending dials and request contexts; closing cannot recall delivered requests | S2, S42: register before dial, cancel contexts, revocation defined as no further access |
| c4 | "All flows logged" contradicts a dropping queue | S31: no record, no flow for allowed flows; the rest best effort with a visible loss counter |
| c5 | Browser key compatibility is first needed in Release B | S21, sections 3, 14, 15 |
