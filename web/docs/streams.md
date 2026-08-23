# Streams & port forwards

Proxy hosts are L7 (HTTP). For everything else — game servers, databases, mail, SSH — quicgate forwards raw TCP/UDP.

## Streams

A stream maps a listen port (or a whole port range) to a target `host:port`, protocol `tcp`, `udp` or `both`. Listeners reconcile live on every config change; UDP uses a session map with idle reaping.

- **Source restriction**: inline CIDRs, or reuse an access list by name — its allow IP/hostname rules become the source filter (L4 sees only IPs, so basic-auth/GeoIP/method rules are ignored there). Empty = anyone, which matters when UPnP has exposed the port to the WAN.
- **PROXY protocol**: send v1/v2 to the target (so the backend sees the real client IP), and/or accept it from an upstream LB.
- **TLS termination**: terminate TLS on a stream with a managed or custom certificate and forward plaintext.
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
