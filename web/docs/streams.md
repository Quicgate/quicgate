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
