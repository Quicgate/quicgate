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
