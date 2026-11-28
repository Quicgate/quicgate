# VPN: devices, people who log in and your local network

quicgate has a VPN built in (WireGuard). It runs inside the quicgate process, without a
network device, extra privileges or a change to the machine's routing. The **VPN** page is
built around four things you may want, and each one is off until you ask for it:

| What you want | What it takes | Section on the page |
|---|---|---|
| Use my own phone or laptop away from home | a device, and a host marked "VPN only" | People, devices and rules |
| Let one device reach something on my local network | a device with the addresses you name | People, devices and rules |
| Let other people log in and add their own devices | a login provider and a login page | People, devices and rules |
| Have quicgate use a service on another network | a router or small machine there | Other networks |

The page opens with these four as a list. Each line says where it stands and has one button
for the next step.

## People, and their devices

A device always belongs to somebody, so the page lists people. **People, devices and rules** has one
row per person who logged in at the login page, and one row called **Added here** for the
devices an admin added on this page. A row says how many devices there are, whether one is
connected now or when one was last seen, what they may reach in short, and how the login is
doing. With more than ten rows a search box (name, group or device name), three filters
(Connected now, Login ended, Blocked) and a page size appear.

Click a row for **the person's page**: the login (with End login and Block), the devices, and
the rules that apply to this person with the reason for each. Click a device to open it in
place. It shows:

- **Last contact** and **first seen.** quicgate writes these down about once a minute, so they
  survive a restart. For a device that is older than this record, the page says "Not seen yet
  since" the day quicgate began to keep it, and not "Never connected".
- **Traffic** since quicgate last started, where the device **connects from**, and its address
  inside the VPN.
- **Who added it**, for a device added here: the admin's account, or "an API token". Devices
  from before 1.21.0 have no such record.
- **What it may reach, and why**: private hosts, and each local address with where it comes
  from (given to this device itself, or from which rule and through which group).
- **Its latest connections to the local network**, read from the connection log
  (`logs/vpn-flows.log`): when, where to, and whether it was allowed, refused (with the reason)
  or ended (with how much was sent and received). Only the latest part of the log is read.
  Visits to private hosts are in the normal request log, not here.

The address in the browser follows along (`#/vpn/person/...`), so the Back button works and a
view can be bookmarked.

Other networks are described in the [Streams & port forwards](streams.md) guide (there they
are the "Reach through" choice of a host or a stream). This guide is about the other three.

## Switch it on

On the **VPN** page, fill in the **address devices connect to**, for example
`vpn.example.com:51820`, and the **port** (forward that UDP port on your router, or let UPnP do
it), then press **Switch on**. quicgate makes its own key at that moment; it is sealed at rest
and no API call returns it. Afterwards these settings live under **VPN settings** at the bottom
of the page.

## Hosts that exist only on the VPN ("private hosts")

On the Proxy hosts page, edit a host and tick **VPN only**. From then on:

- The host is served inside the VPN and nowhere else. On the public side the name gets the
  same answer as a name quicgate has never heard of, and the TLS handshake for it fails the
  same way. Nothing tells a visitor that the host exists.
- Devices find it without any DNS work on your side. The setup file a device gets uses
  quicgate as its DNS server, and quicgate answers the names of its own hosts with its address
  inside the VPN. Other names are passed on to the resolvers quicgate itself uses.
- The certificate is the usual one. For a name that has no public DNS record, use DNS-01 or an
  uploaded certificate: HTTP-01 cannot reach a host that is not served publicly.

Every device on the VPN reaches every private host, unless an access list says otherwise (see
"VPN rules in access lists").

## Devices you add yourself

**VPN, Add a device.** Give it a name and choose what it may reach:

- **Private hosts only.** Right for most phones and laptops.
- **Private hosts, and addresses on my local network.** For things that are not a web page
  behind quicgate: a file share, remote desktop, SSH, a printer. See the next section.

The browser makes the key, so the private half never reaches quicgate; if you would rather
make the tunnel in the WireGuard app first, open "Technical details" and paste its public key.
The second step of the dialog lists what to do on the device: install the WireGuard app,
download the **setup file** and open it in the app, switch the tunnel on. The setup file is
shown **once** and is not stored anywhere: when it is lost, remove the device and add it again.

The device appears under **Added here** in "People, devices and rules". The "Allowed" switch on its
row pauses it.

**Removing a device is final.** Its key cannot be registered again, open connections are
closed at once, and its address inside the VPN stays out of use so that nothing of the old
device can end up at a new one.

## One device, one address on your local network

Local network access has to be on: **VPN settings, Local network access**. It is marked
experimental (see "Local network access" below for what it does and does not do).

In **Add a device**, choose "Private hosts, and addresses on my local network" and fill in a
line per destination:

- **Name**: what you call it, like NAS. For reading only.
- **Address**: one address like `192.168.1.10`, or a whole network like `192.168.1.0/24`.
  Name a single address where you can.
- **What for**: file sharing, a web page, remote desktop, SSH, printing, everything on this
  address, or ports of your own. This fills in the ports.

Under the lines the dialog says whether quicgate would let the device get there, and why not
(a protected address, quicgate itself, a network that is reached through another network).

**Nobody logs in behind such a device.** Whoever holds its setup file reaches the addresses
you named until you remove the device or its end date passes, and no login provider can cut
it off. That is why it costs more than a plain device:

- your **password and a two-factor code**, and your account must have two-factor on (your name
  at the top right, Account, "Sign-in & 2FA");
- an **end date**, filled in with a year from now. "No end date" has to be ticked on purpose.
  After the end date the device stops working altogether;
- the Overview page keeps reminding you that such devices exist;
- an API token cannot do it.

**Changing it later.** Open the device (People, devices and rules, Added here, the device). "Change
access" there opens the same choices and asks for
the same confirmation, also when you only take addresses away. On quicgate's side the change is
in force at once. The device itself still has its old setup file, and quicgate cannot make a
new one because it never has the device's private key. So the page shows the one line to put
into the WireGuard app on that device: edit the tunnel and replace the line that starts with
`AllowedIPs`. Until then the device does not send traffic for new addresses into the VPN. On a
phone it is often easier to remove the device and add it again.

### If you had break-glass devices

Before 1.20 there was a separate kind of device for this, the break-glass device, and there
could be two. They are now ordinary devices with local addresses: the ones you have keep
working and show up under "Added here", and there is no limit of two. One use for them
stays worth remembering: if your login provider itself is behind the VPN, an outage locks
everybody out, you included. A device of your own with the addresses you need to repair it is
the way back in. Keep its setup file offline.

## VPN rules in access lists

An access list has a fourth kind of rule next to IP, hostname and country: **On the VPN**. It
matches requests that came through the VPN, and says who:

- anyone on the VPN, any other network, any device,
- one other network or one device,
- a group, one person, or everybody from one login provider (devices that people added at the
  login page, see below).

Two properties keep this safe to switch on:

- A request from outside the VPN **never** matches a VPN rule, and a request from inside the
  VPN **never** matches an IP or country rule. So adding the VPN cannot change who passes a
  list you already have, and an address inside the VPN cannot be used to slip through an
  "allow 10.0.0.0/8" rule.
- A group or a person is always named together with its login provider. "admins" from one
  provider is never "admins" from another.

Requests from inside the VPN are not counted toward automatic bans.

## People who log in

For family or colleagues: they sign in with their own account and add their own devices. You
do not hand out files. Until it is set up, "People, devices and rules" shows what it takes:

1. **A login provider.** The service people sign in with, such as Keycloak or Authentik. Add
   it on the Access control page, where it is called an identity provider.
2. **A login page.** A proxy host of the type **VPN portal**, for example `vpn.example.com`.
   Choose the login provider and say who may add devices (a group, single people, or
   everybody from that provider). Register `https://vpn.example.com/.qg/vpn/callback` as a
   redirect URI at the provider.
3. **What they may reach.** Private hosts straight away. For addresses on your local network,
   add a **rule** (see below).

The login page has to be reachable without the VPN: it is where people go to get the VPN
*back*. Starting a login and adding a device are limited to ten per minute per client address.
It is served over **HTTPS only**, so the host needs a certificate: plain HTTP is redirected,
and nothing but the redirect is ever answered there. Behind a proxy that terminates TLS, that
proxy has to be listed under trusted proxies and send `X-Forwarded-Proto: https`.

What a person sees: log in, name a device, download the setup file. What quicgate does with
that login is stricter than an ordinary web login, because a setup file outlives a browser
session. The settings named here are under **Login rules** in "People, devices and rules":

- **The login has to be fresh.** quicgate asks the provider to authenticate the person now
  (`max_age`) and checks the `auth_time` the provider states. A browser that was still logged in
  from this morning is not enough. The window is **How recent a login must be**, 15 minutes by
  default.
- **The provider has to issue a refresh token** (scope `offline_access`). Without one the login
  is refused: quicgate would have no way to notice later that the account was switched off.
- **quicgate asks again, every few minutes** (**Check with the login provider every**, 10 by
  default), by redeeming the refresh token. When the provider refuses, or names another person,
  the devices of that person are taken off the VPN at once and their open connections are
  closed.
- **An outage is not a refusal.** When the provider cannot be reached, nothing is extended. The
  devices keep working until the current check runs out, plus **Keep working when it cannot be
  reached** if you set that (0 by default), and no longer.
- **However well the checks go, the person logs in again** after **Log in again after** (30
  days by default).
- **Adding a device takes a login that is fresh at that moment.** A login page that has been
  open since this morning shows your devices, and asks you to log in again before it adds one.
- **What is open ends with the login.** When a login lapses, is ended, or reaches its limit,
  the connections the person's devices hold are closed at that moment, not just new ones
  refused.
- A device keeps its setup file across all of this. After a lapse the person logs in at the
  login page and the same device works again.

Each person who logged in has a row in "People, devices and rules", and a page of their own behind
it. **End login** there takes a person's devices off until they log in again. **Block** keeps
them off whatever the provider says, until you lift it on the same page.

### Rules: what people may reach on your local network

Rules live with the people they are for, in the same card. **Add a rule** is at the top of
"People, devices and rules".

- A rule for **one person** shows on that person's row (the addresses under "May reach", with
  the rule's name in small print) and is changed or removed on their page, under "Rules that
  apply". "Add a rule for this person" is there too.
- A rule for **a group or for everybody** is listed at the bottom of the card, with how many
  people and devices it covers today. Each person it covers also shows it on their page, with
  the reason ("through the group family").
- A rule for a person who has not logged in yet has no row to live on, so it is listed at the
  bottom of the card as well. No rule is ever out of sight.

A rule says *for whom* (a group, a person, everybody from one login provider) and *may reach*
(the same lines as for a device: name, address, what for). A person gets what every rule that
names them allows; there are no "deny" rules, and what no rule allows is refused. The rule
dialog has a **Check an address** box that says whether a destination would get through, and
why not.

A device that was set up before a rule existed does not know about the new addresses: its
setup file was written when it was added. The person adds the device again at the login page,
or puts the addresses into the `AllowedIPs` line in the WireGuard app by hand.

### What the login provider has to support

| Needed | Why | Keycloak |
|---|---|---|
| refresh tokens for the client, scope `offline_access` | the repeated check | client scope `offline_access` assigned to the client |
| an `auth_time` claim in the ID token | the fresh-login check | sent by default |
| honouring `max_age` | the fresh-login check | yes |
| groups in the ID token **of a refresh response**, or at the UserInfo endpoint | rules by group | add a Group Membership mapper, with "Add to ID token" and "Add to userinfo" on |

If your provider leaves the groups out of refreshed tokens, set **Read groups from** to "the
UserInfo endpoint" on the login page's host. quicgate treats a missing groups claim as "in no
group", never as "unchanged": a person whose groups it cannot see loses what the groups gave
them.

This part is tested against a synthetic login provider, including refusals, outages, token
rotation, another person's answer, and an admin ending a login while a check is in flight. It
has not been qualified against a live Keycloak yet. Try it against yours before you depend on it.

## Local network access (experimental)

Off by default (**VPN settings, Local network access**), and marked experimental until the
code has had an outside review. With it on, a device reaches the addresses that were named for
it: on the device itself when you added it, or in the rules for the person who added it.

How it works, and what follows from it:

- quicgate is not a router. It ends each connection in its own network stack and opens a new
  one to the destination. The destination sees **quicgate's address**, not the device's.
  Devices cannot talk to each other, and nothing on the local network can open a connection to
  a device.
- TCP and UDP only. No ICMP, so `ping` does not work through it. IPv4 only.
- **Whatever a device or a rule was given, these are refused:** every port quicgate itself
  listens on (the admin page above all), loopback, link-local (which includes cloud metadata
  addresses), multicast and broadcast, the addresses used inside the VPN and the networks
  behind other networks.
- **This machine is not part of "the local network".** quicgate's own addresses, the default
  gateway (in Docker that is the host, where published ports live) and the addresses you list
  under **Addresses nobody may reach** are not covered by a line like `192.168.1.0/24`.
  Reaching another service on one of them takes a line for exactly that address with explicit
  ports, and quicgate's own listeners stay out of reach even then. "Check an address" under
  VPN settings says whether an address is protected.
- Every connection is recorded in `logs/vpn-flows.log` before it is allowed: who, which
  device, where to, allowed or refused and why. "Recorded" means written to the file, not
  queued: if the log cannot be written (a full disk, a directory that cannot be created, a disk
  that hangs), connections to the local network are refused until it can, and the Overview page
  says so. Records of *refused* and ended connections are best effort; what is lost of them is
  counted. A record is handed to the operating system, not forced to the disk, so a power cut
  can still lose the last ones.
- Limits per device and in total keep one device from exhausting quicgate.
- When a login lapses, a device is removed or reaches its end date, or its addresses or a rule
  change, the connections that are no longer allowed are closed, not just new ones refused.

### In Docker on a bridge network

quicgate sees its container address there, not the Docker host's. A published port
(`-p 81:81`) lives on the host's address, which quicgate cannot know, so a device that was
given the host's address would reach quicgate's own admin port through the back door. When
quicgate detects this situation it refuses to switch local network access on until you either
list the Docker host's addresses under **Addresses nobody may reach**, or tick **No quicgate
port within reach** to confirm that no quicgate port is published on an address a device could
be given. With `network_mode: host` quicgate sees the real addresses and protects them itself.

## What this is not

- Not a full-tunnel VPN: there is no route to the internet through quicgate, and the setup
  files only send quicgate's address inside the VPN and the named addresses into it.
- Not a mesh. Devices reach quicgate, and through it what was named for them. Other networks
  are reached by quicgate's hosts and streams, not by devices.
- Streams are not reachable from devices: only proxy hosts and named local addresses are.
- The official WireGuard apps for iOS and Android have not been tested by the project. The key
  format the browser produces is verified against the WireGuard implementation quicgate embeds,
  and the setup file is the standard format, but nobody has imported one on a phone yet.
  Pasting the public key of a tunnel made in the app always works.
