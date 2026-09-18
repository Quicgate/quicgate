# VPN: devices, the portal and LAN access

quicgate has a WireGuard endpoint built in. It runs inside the quicgate process, without a
network device, extra privileges or a change to the host's routing. It does three separate
things, and each one is off until you ask for it:

| | What it is for | Who holds the key |
|---|---|---|
| **Sites** | quicgate reaches upstreams on *another* network | a router or a small box at the other location |
| **Devices** | a phone or a laptop reaches hosts that quicgate serves **in the tunnel only** | a person's device |
| **LAN access** *(experimental)* | a person who logged in reaches parts of the network quicgate is on | a person's device, after single sign-on |

Sites are described in the [Streams & port forwards](streams.md) guide. This guide is about the
other two.

## Switch it on

On the **VPN** page, enable the endpoint, pick a UDP port (forward it on your router, or let UPnP
do it) and fill in the **public address** people's devices will connect to, for example
`vpn.example.com:51820`. quicgate makes its own key at that moment; it is sealed at rest and no
API call returns it.

## Hosts that exist only on the VPN

Edit a host and tick **VPN only**. From then on:

- The host is served inside the tunnel and nowhere else. On the public listeners the name gets
  the same answer as a name quicgate has never heard of, and the TLS handshake for it fails the
  same way. Nothing tells a visitor that the host exists.
- Devices find it without any DNS work on your side. The configuration a device gets uses
  quicgate as its DNS server, and quicgate answers the names of its own hosts with its tunnel
  address. Other names are passed on to the resolvers quicgate itself uses.
- The certificate is the usual one. For a name that has no public DNS record, use DNS-01 or an
  uploaded certificate: HTTP-01 cannot reach a host that is not served publicly.

## Devices you add yourself

**VPN, Add device.** Give it a name. The browser makes the keypair, so the private key never
reaches quicgate; if you would rather make the tunnel in the WireGuard app first, paste its
public key instead. The configuration is shown **once**, with a button to download it as a
`.conf` file that the WireGuard apps import. It is not stored anywhere: when it is lost, revoke
the device and add it again.

A device you add this way reaches quicgate's hosts in the tunnel. It never gets LAN access.

**Revoking is final.** The key cannot be registered again, open connections are closed at once,
and the tunnel address stays out of use so that nothing of the old device can end up at a new
one.

## VPN rules in access lists

An access list has a fourth kind of rule next to IP, hostname and country: **On the VPN**. It
matches requests that came through the tunnel, and says who:

- anyone on the VPN, any site, any device,
- one site or one device,
- a group, one person, or everybody from one identity provider (devices that people enrolled at
  the portal, see below).

Two properties keep this safe to switch on:

- A request from outside the tunnel **never** matches a VPN rule, and a request from inside the
  tunnel **never** matches an IP or country rule. So adding the VPN cannot change who passes a
  list you already have, and a tunnel address cannot be used to slip through an "allow
  10.0.0.0/8" rule.
- A group or a person is always named together with its identity provider. "admins" from one
  provider is never "admins" from another.

Requests from inside the tunnel are not counted toward automatic bans.

## The portal: people add their own devices

Add a host of type **VPN portal**, for example `vpn.example.com`, choose the identity provider,
and say who may add devices (a group, single people, or everybody from that provider). Register
`https://vpn.example.com/.qg/vpn/callback` as a redirect URI at the provider.

The portal has to be reachable without the VPN: it is where people go to get the VPN *back*.

What a person sees: log in, name a device, download the configuration. What quicgate does with
that login is stricter than an ordinary web login, because a VPN configuration outlives a
browser session:

- **The login has to be fresh.** quicgate asks the provider to authenticate the person now
  (`max_age`) and checks the `auth_time` the provider states. A browser that was still logged in
  from this morning is not enough. The window is the **Fresh login** setting, 15 minutes by
  default.
- **The provider has to issue a refresh token** (scope `offline_access`). Without one the login
  is refused: quicgate would have no way to notice later that the account was disabled.
- **quicgate asks again, every few minutes** (the **Check every** setting, 10 by default), by
  redeeming the refresh token. When the provider refuses, or names another person, the devices
  of that person are taken off the endpoint at once and their open connections are closed.
- **An outage is not a refusal.** When the provider cannot be reached, nothing is extended. The
  devices keep working until the current check runs out, plus the **outage grace** if you set one
  (0 by default), and no longer.
- **However well the checks go, the person logs in again** after **Log in again after** (30 days
  by default).
- A device keeps its configuration across all of this. After a lapse the person logs in at the
  portal and the same device works again.

On the VPN page, **People** shows every login with its state. **End** takes a person's devices
off until they log in again. **Block** keeps them off whatever the provider says, until you lift
it.

### Requirements for the identity provider

| Needed | Why | Keycloak |
|---|---|---|
| refresh tokens for the client, scope `offline_access` | the repeated check | client scope `offline_access` assigned to the client |
| an `auth_time` claim in the ID token | the fresh-login check | sent by default |
| honouring `max_age` | the fresh-login check | yes |
| groups in the ID token **of a refresh response**, or at the UserInfo endpoint | group policies and group rules | add a Group Membership mapper, with "Add to ID token" and "Add to userinfo" on |

If your provider leaves the groups out of refreshed tokens, set **Read groups from** to "the
UserInfo endpoint" on the portal host. quicgate treats a missing groups claim as "in no group",
never as "unchanged": a person whose groups it cannot see loses what the groups gave them.

This part is tested against a synthetic identity provider, including refusals, outages, token
rotation, another person's answer, and an admin ending a login while a check is in flight. It
has not been qualified against a live Keycloak yet. Try it against yours before you depend on it.

## LAN access (experimental)

Off by default, and marked experimental until the code has had an outside review. With it on, a
person who logged in at the portal can reach the destinations their **policies** name, on the
networks the quicgate machine is on.

A policy says *for whom* (a group, a person, everybody from one provider) and *may reach* (IPv4
prefixes in private address space, with a protocol and ports). A person gets the routes of every
policy that names them; there are no deny rules. The policy editor has a **Try it** box that
says whether a destination would pass, and why not.

How it works, and what follows from it:

- quicgate is not a router. It terminates each connection in its own userspace network stack
  and opens a new one to the destination. The destination sees **quicgate's address**, not the
  device's. Devices cannot talk to each other, and nothing on the LAN can open a connection to a
  device.
- TCP and UDP only. No ICMP, so `ping` does not work through it. IPv4 only.
- **Whatever a policy says, these are refused:** every port quicgate itself listens on (the
  admin UI above all), loopback, link-local (which includes cloud metadata addresses), multicast
  and broadcast, the tunnel network itself and the networks behind sites.
- **This machine is not part of "the LAN".** quicgate's own addresses, the default gateway (in
  Docker that is the host, where published ports live) and the addresses you list under
  **Protected endpoints** are not covered by a route like `192.168.1.0/24`. Reaching another
  service on one of them takes a route for exactly that address (`/32`) with explicit ports, and
  quicgate's own listeners stay out of reach even then.
- Every flow is recorded in `logs/vpn-flows.log` before it is allowed: who, which device, where
  to, allowed or refused and why. If the log cannot keep up, a flow that would have been allowed
  is refused rather than let through unrecorded; records of *refused* flows are dropped and
  counted, and the Overview page says so.
- Limits per device and in total keep one device from exhausting quicgate.
- When a login lapses, a device is revoked, or a policy changes, the flows that are no longer
  allowed are closed, not just new ones refused.

### In Docker on a bridge network

quicgate sees its container address there, not the Docker host's. A published port
(`-p 81:81`) lives on the host's address, which quicgate cannot know, so a policy that grants
the host's address would reach quicgate's own admin port through the back door. When quicgate
detects this situation it refuses to switch LAN access on until you either list the Docker
host's addresses under **Protected endpoints**, or confirm that no quicgate port is published
on an address a policy can reach. With `network_mode: host` quicgate sees the real addresses and
protects them itself.

### Break-glass devices

If the identity provider is itself behind the VPN, an outage locks everybody out, you included.
A break-glass device is the way back in: it has LAN routes of its own and no login behind it.
That makes it the most dangerous thing on the page, so it costs the most to make: your password
and a two-factor code (the admin account must have 2FA on), at most two of them, and an expiry
date unless you state that it shall not expire. Keep the configuration offline. The Overview
page reminds you that they exist.

## What this is not

- Not a full-tunnel VPN: there is no route to the internet through quicgate, and the device
  configurations only send quicgate's tunnel address and the granted prefixes into the tunnel.
- Not a mesh. Devices reach quicgate, and through it what a policy grants. Sites are reached by
  quicgate's upstreams, not by devices.
- The official WireGuard apps for iOS and Android have not been tested by the project. The key
  format the browser produces is verified against the WireGuard implementation quicgate embeds,
  and the configuration is the standard format, but nobody has imported one on a phone yet.
  Pasting the public key of a tunnel made in the app always works.
