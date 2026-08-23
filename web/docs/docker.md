# Docker labels (config from containers)

quicgate can read container labels and turn them into hosts and streams automatically — the Traefik provider idea, minus the router/service/middleware label soup. Opt a container in with `quicgate.enable=true` and it appears on the **Docker** page; usually two labels is all it takes. Nothing is persisted: derived routes re-derive from live containers on every change and at startup.

Enable the provider by mounting the daemon socket (read-only is enough — quicgate only ever lists, inspects, and watches events, it never writes) and setting `QG_DOCKER=1`:

```yaml
services:
  quicgate:
    image: ghcr.io/quicgate/quicgate:1
    network_mode: host
    environment:
      QG_DOCKER: "1"
      QG_DOCKER_DOMAIN: apps.example.com    # optional: default base domain
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - quicgate-data:/data

  grafana:
    image: grafana/grafana
    ports: ["3000:3000"]
    labels:
      quicgate.enable: "true"
      quicgate.host: metrics.example.com    # or omit this, with QG_DOCKER_DOMAIN set
```

## Labels

| Label | Meaning | Default |
|---|---|---|
| `quicgate.enable` | opt this container in (**required**) | off |
| `quicgate.host` | public hostname(s), comma-separated | `<name>.<default-domain>` if one is set |
| `quicgate.port` | the app's port **inside the container** | auto if exactly one candidate |
| `quicgate.exclude-ports` | ports to ignore when auto-detecting | none |
| `quicgate.scheme` | upstream scheme `http` / `https` | `http` |
| `quicgate.tls-skip-verify` | trust a self-signed upstream | `false` |
| `quicgate.tls` | obtain a Let's Encrypt cert (public side) | `on` |
| `quicgate.access-list` | attach an existing access list by name | none |
| `quicgate.streams` | raw L4 forwards, comma-separated `[listen:]container[/proto]` | none |

`quicgate.streams` exposes non-HTTP ports as TCP/UDP streams, e.g. `quicgate.streams=25565, 2222:22/tcp, 53/udp` (proto `tcp`/`udp`/`both`, default `tcp`; `listen:` remaps the public port). Stream ports are automatically excluded from HTTP port auto-detection, so a container with a web port and a game port needs no `exclude-ports`. A container can be HTTP-only, streams-only (no hostname needed), or both.

Manual hosts always win a naming conflict — a label can never silently override a host you configured by hand. Anything beyond these labels (custom locations, header rules, mTLS, rate limits) lives in the UI: use **Convert to host** on the Docker page to turn a derived container into editable configuration with no downtime.

## How quicgate reaches containers

One rule: quicgate connects to the **Docker host's address** on the container's **published port**. `quicgate.port` names the app's port *inside* the container; quicgate uses that port's published host mapping (a `network_mode: host` container is reached at that port directly). So a container must publish the port you want routed. The local host's address defaults to `127.0.0.1` (`QG_DOCKER_HOST_ADDR`).

## Multiple Docker hosts

quicgate can watch several daemons at once. Give it a JSON list of endpoints (in `QG_DOCKER_ENDPOINTS`, or the **Docker hosts** box on the Docker page), each with a name, a connection, and the address where *its* published ports are reachable from quicgate:

```json
[
  {"name": "local",    "connect": "/var/run/docker.sock",    "address": "127.0.0.1"},
  {"name": "docker92", "connect": "tcp://192.168.1.92:2375", "address": "192.168.1.92"}
]
```

A container on `docker92` is then reached at `192.168.1.92:<published port>`. Reach a remote daemon through a **read-only socket proxy** (below) exposing `tcp://` on the LAN. Endpoint-list changes apply on restart; the Docker page shows each host's connection state.

## Socket security

The provider is read-only, but the socket still grants broad access to the daemon. Mount it `:ro`, and for least privilege put a read-only socket proxy (e.g. `tecnativa/docker-socket-proxy` with only `CONTAINERS=1` and `EVENTS=1`) in front of it and point `QG_DOCKER_SOCKET` at the proxy.
