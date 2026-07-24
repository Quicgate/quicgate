# Benchmarks

quicgate ships a reproducible benchmark suite so you can see the engine's
capacity and run it yourself. Numbers vary enormously by CPU, so treat these as
a ballpark and reproduce on your own hardware.

## Run it

```bash
go test -run='^$' -bench=. -benchmem -benchtime=3s ./internal/engine 2>/dev/null
```

(`2>/dev/null` just hides the engine's start-up logs so the benchmark table is clean.)

## What is measured

Each benchmark builds a real engine with one proxy host in front of a trivial
local backend, then drives requests through the **full pipeline** (routing →
access list / middleware → reverse proxy). The client, quicgate and the backend
all run on the same machine over loopback with no TLS, so these are **full
round-trip, single-box** figures: a real deployment where the client and the
backend live on other machines leaves quicgate more CPU and goes higher.

| Benchmark | What |
|---|---|
| `RouteLookup` | the routing-table lookup every request pays |
| `ServeProxy` | full request pipeline to a local backend (in-process) |
| `ServeProxyAccessList` | same, with an IP access list evaluated per request |
| `ProxyThroughput` | end-to-end requests/sec over a real loopback socket |
| `CacheHitThroughput` | same, but responses served from the per-host cache |

## Results

Measured on an **AMD Ryzen 7 9800X3D** (8 cores / 16 threads), Go 1.25,
loopback, no TLS:

| Benchmark | ns/op | ≈ requests/sec | allocs/op |
|---|---:|---:|---:|
| Route lookup | 9.3 | ~108,000,000 | 1 |
| Proxy to local backend | 19,500 | ~51,000 | 105 |
| Proxy + IP access list | 17,500 | ~57,000 | 105 |
| Proxy throughput (real socket) | 22,000 | ~45,000 | 158 |
| Cache hit | 5,500 | ~180,000 | 71 |

How to read them:

- **Routing is free.** A host lookup is ~9 ns and one allocation; the router is
  never the bottleneck no matter how many hosts you configure.
- **Access lists are free.** Adding an IP access list moves throughput by less
  than run-to-run noise.
- **~45,000 requests/sec proxied** end-to-end with the load generator, quicgate
  and the backend all fighting for the same 8 cores. Move the client and backend
  off-box and quicgate keeps the cores to itself.
- **Cache hits are ~4× faster** (~180,000/sec) because the backend is bypassed
  entirely.

## Real-world load test

For end-to-end numbers on your deployment (real network, TLS, concurrency),
point a load generator at a running instance proxying to a fast static backend:

```bash
# e.g. bombardier (https://github.com/codesenberg/bombardier)
bombardier -c 200 -d 30s https://app.example.com/

# or wrk (https://github.com/wg/wrk)
wrk -t8 -c200 -d30s https://app.example.com/
```

Keep the backend trivial (a static file or a tiny "ok" responder) so you measure
quicgate, not the app behind it. Run the load generator from a *different*
machine than quicgate for a true server-capacity number. HTTP/3 (UDP 443) needs
a client that speaks h3.

## Real-world (live homelab)

Measured against the live deployment: one LAN client -> quicgate on a **6-vCPU
homelab VM that also runs ~50 other containers** -> an nginx backend serving a
real **90 KB** page, over real TLS (HTTP/2), LAN-direct.

| Test | Result |
|---|---|
| GET the 90 KB page (200) | **566 req/s, 51 MB/s (~408 Mbit/s)**, p50 70 ms, p99 79 ms |
| Small responses over TLS, single client | **~5,000 req/s**, p50 7 ms, p99 19 ms |

Page-serving throughput stayed **flat at ~566 req/s from 40 to 200 concurrent
connections** while latency grew linearly (70 -> 177 -> 354 ms) -- the signature
of a fixed pipe *upstream* of the proxy. Here that pipe is the **single client's
~400 Mbit/s link**, not quicgate, which rejected small requests at 5,000+/s with
CPU to spare. Serving a real page it saturated the available bandwidth and had
headroom left; its true page-serving ceiling needs several off-box clients (one
machine maxes its own link first).

## How it compares to nginx / Traefik / Pangolin

quicgate's engine is Go `net/http` + `httputil.ReverseProxy` -- the **same class
as Traefik and Zoraxy** (both Go). Expect it to sit in Traefik's ballpark,
behind bare **nginx** (C, the throughput reference), and ahead of heavier stacks
that add layers: Nginx Proxy Manager, or **Pangolin**, which runs on Traefik
*plus* a WireGuard tunnel layer, so its proxy ceiling is Traefik's minus tunnel
overhead.

Published figures, for orientation only -- **different hardware, payloads, TLS
settings and tools, so not a head-to-head:**

| Proxy | req/s | p99 | Setup | Source |
|---|---:|---:|---|---|
| nginx | ~100,600 | 28 ms | 16 vCPU, no TLS, 1000 conns | hhf.technology |
| Traefik v3 | ~74,000 | 36 ms | 16 vCPU, no TLS, 1000 conns | hhf.technology |
| **quicgate** | **~45,000** proxied / **~180,000** cache-hit | -- | dedicated 8-core, small response, loopback (client + backend share the cores, so a floor) | this repo, `go test -bench` |
| Zoraxy (Go) | 155 | 263 ms | 1 vCPU / 1 GB, TLS, real backend | deployn.de |
| NPM+ (nginx) | 102 | 413 ms | 1 vCPU / 1 GB, TLS, real backend | deployn.de |
| NPM (nginx) | 91 | 605 ms | 1 vCPU / 1 GB, TLS, real backend | deployn.de |

Those are two different scenarios: the top rows are a 16-vCPU, no-TLS
raw-throughput test (tens of thousands of req/s); the bottom rows are a
constrained 1-core box with TLS in front of a real app (everything collapses to
double digits, and the Go proxy Zoraxy edges out the nginx-based NPM). The honest
reading: for any modern proxy under ~10k req/s per instance -- which covers
essentially all self-hosted and small-fleet use -- the choice is not
throughput-bound, and quicgate is comfortably in that range. quicgate's own
micro-benchmark (~45k proxied req/s on a shared 8-core, a floor) puts it in the
Go-proxy class alongside Traefik/Zoraxy, well clear of the layered NPM/Pangolin
stacks. Run `go test -bench=. ./internal/engine` on your own hardware for a
number that's actually comparable to your workload.

Sources: nginx / Traefik figures from
[hhf.technology's Traefik v3 vs Nginx analysis](https://hhf.technology/blog/traefik-vs-nginx);
NPM / Zoraxy figures from
[deployn.de's 2025 reverse-proxy benchmark](https://deployn.de/en/blog/reverse-proxy-benchmark-2025/).
