# Streams & port forwards

Proxy hosts are L7 (HTTP). For everything else — game servers, databases, mail, SSH — quicgate forwards raw TCP/UDP.

## Streams

A stream maps a listen port (or a whole port range) to a target `host:port`, protocol `tcp`, `udp` or `both`. Listeners reconcile live on every config change; UDP uses a session map with idle reaping.

- **Source restriction**: inline CIDRs, or an access list. An access list is evaluated in order, exactly as for a proxy host (allow and deny, IP, hostname and GeoIP country rules, first match wins, no match denies), with two differences a raw connection forces: a rule limited to HTTP methods can only narrow access (its *allow* never admits a connection, its *deny* always applies), and a list that needs basic-auth credentials (*satisfy all* with users, or users without address rules) admits no connection at all. No restriction = anyone, which matters when UPnP has exposed the port to the WAN. A configured restriction that yields nothing usable (every CIDR unparsable, a list that no longer exists) keeps the stream closed.
- **PROXY protocol**: send v1/v2 to the target (so the backend sees the real client IP), and/or accept it from an upstream load balancer. Accepting requires **trusted proxies**: only a peer in that list may state the client address, and it must send a valid header (v1 or v2) within 5 seconds or the connection is closed. Any other peer connects as itself: its own address is checked against the source restriction and nothing it sends is read as a header.
- **TLS termination**: terminate TLS on a stream with a custom certificate (uploaded, self-signed or read from files) and forward plaintext. Managed ACME certificates are not available to streams. If the certificate is missing or unreadable the stream does not start rather than falling back to plaintext, and replacing the certificate restarts the listener with the new one.
- **Status**: a stream that is saved but cannot run (a port held by another process, a missing certificate, PROXY accept without trusted proxies) is shown as *not running* with the reason, in the list and when saving.
- **Changes apply to open connections**: when a stream's settings change, or it is disabled or removed, the TCP connections and UDP sessions it admitted are closed with its old listener, so a new source restriction also ends connections that no longer qualify. Clients reconnect and are checked against the new settings. Editing one stream leaves the connections of other streams alone.
- **Limits**: each UDP listener keeps at most 1024 client sessions and at most 64 per source address (new sources, or new ports of an address at its limit, are dropped while full), each TCP listener at most 4096 concurrent connections, and a TLS-terminating stream allows 10 seconds for the handshake.
- **SNI passthrough routing**: route TLS connections by SNI hostname to different backends on one port, without terminating.
- Ports already claimed by the engine (80/443/admin) are rejected at validation time.

## Router port forwards (UPnP)

With `QG_UPNP=1`, quicgate manages your router's port forwards over UPnP IGD:

- Maps 80 + 443 (tcp+udp) and every enabled stream port to itself automatically; leases are re-added every 30 minutes and unmapped when a stream is deleted or quicgate shuts down. Conflicts fail soft.
- The **Port forwards** page adds pure router forwards to quicgate's own machine for things quicgate does not proxy at all — they exist only as router mappings, self-healing after router reboots.
- Most routers only allow a device to map ports to *itself* (the FRITZ!Box does); forwards to other machines stay manual router config, or become quicgate streams instead.

## Choosing between them

| You want | Use |
|---|---|
| HTTPS website/API with certs, headers, auth | Proxy host |
| Non-HTTP service through quicgate | Stream |
| Many TLS services sharing port 443 without termination | Stream + SNI routing |
| Router hole-punch to a port on the quicgate machine | Port forward (UPnP) |

Note that a forwarded stream hides the original client IP from the backend unless you enable PROXY protocol (and the backend supports it). For protocols with their own notion of client identity (SMTP spam filtering, for example), a direct router forward to the real server is often better than a stream.

## WireGuard sites

A **site** lets quicgate reach upstreams on a network it is not on. The site is an ordinary
WireGuard peer at that location: a router with WireGuard (OpenWrt, pfSense, a FRITZ!Box), a
small Linux box, a VPS. Once a site exists, a proxy host or a stream gets a **Reach through**
choice next to its upstream. Two typical uses:

- **A service at another location.** quicgate at home, a camera system at the cabin: the cabin's
  router is the site.
- **No public address at home.** quicgate on a VPS, the home network behind carrier NAT: a box at
  home is the site and calls in.

### Set it up

1. **VPN page, switch WireGuard on.** Pick the UDP port (51820 by default) and forward it on the
   router in front of quicgate, or let `QG_UPNP=1` map it. Fill in the public address sites will
   call (`vpn.example.com:51820`).
2. **Add site.** Name it, list the networks behind it (`192.168.50.0/24`), and give its endpoint
   if quicgate can call it (`cabin.example.net:51820`). Leave the endpoint empty for a site that
   can only call in.
3. **Take the configuration.** The browser makes the site's keypair and shows a complete
   WireGuard configuration **once**: quicgate never sees the private key and cannot show the
   configuration again. On a page without HTTPS the browser cannot make keys; run
   `wg genkey | tee private.key | wg pubkey` on the site and paste the public key instead.
4. **On the site**, load the configuration and let it forward between the tunnel and its network:

   ```bash
   sysctl -w net.ipv4.ip_forward=1
   # either NAT, which needs nothing else on the site's network:
   iptables -t nat -A POSTROUTING -s 10.77.0.1/32 -o eth0 -j MASQUERADE
   # or a route back to 10.77.0.1 via this box on the site's router
   ```

5. **Use it.** Edit a proxy host, set its upstream to the address on the remote network and
   choose the site under *Reach through*. The choice covers the host's pool and locations too.

### What to expect

- **Never a fallback.** An upstream that names a site is only ever dialled inside the tunnel. If
  the site or the tunnel is down the host answers 502; the address is never tried on the local
  network, where it may belong to another machine. An address outside the site's networks is
  refused.
- **Status.** The VPN page shows each site's last handshake, traffic and open connections. "up"
  means a handshake in the last three minutes. A site shows "waiting" until traffic flows:
  WireGuard only shakes hands when there is something to send.
- **Restarts.** A site with an endpoint is back the moment quicgate is. A site that calls in
  notices a restart only when its own timer fires: up to about 40 seconds with the default
  keepalive of 25. Give a site an endpoint wherever it has a reachable address.
- **Dynamic DNS.** Endpoint names are looked up again every five minutes. A name that does not
  resolve only affects its own site, which can still call in.
- **Moving networks.** Giving a site a network that another site had, or changing its key,
  rebuilds the VPN endpoint, which interrupts all VPN traffic for a moment.
- **Limits.** IPv4, TCP and UDP. No ping to the remote network, no multicast. Health checks of
  upstreams behind a site are a TCP connect through the tunnel.
- Secrets: the server key and the preshared keys are sealed in the database like every other
  secret; see the configuration reference for the key and its backup.
