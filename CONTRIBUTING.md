# Contributing to quicgate

Thanks for your interest. quicgate is a small, opinionated project, so a little
context up front will save everyone time.

## Project philosophy

Three principles shape almost every design decision. Please keep to them:

1. **One binary, one container.** The engine, ACME client, streams, admin UI and
   API are a single Go program with a single SQLite file. Avoid changes that
   introduce a sidecar service, an external database, or a heavy runtime
   dependency.
2. **Typed options, never a config escape hatch.** There is deliberately no
   free-text nginx/Traefik snippet field. If a feature needs a new knob, add it
   as a *typed, validated* option on the host/stream/access-list, wired through
   the store, the engine, and the UI. A "just let users paste raw config" PR will
   be declined — that is the thing quicgate exists to avoid.
3. **No silent drops.** Unknown JSON fields are rejected; failed reloads surface
   as errors. Keep it that way.

## Development setup

You need Go 1.26+ (see `go.mod`). No build step for the UI — it is vanilla JS/CSS
embedded via `go:embed`.

```bash
git clone https://github.com/maferick/quicgate
cd quicgate

# run without TLS/QUIC on high ports, isolated data dir
QG_TLS=off QG_HTTP=:8090 QG_ADMIN=:8091 QG_DATA=./devdata go run .
```

Open `http://localhost:8091`, log in with `admin@example.com` / `changeme` (you'll
be forced to change it), and start clicking.

Build checks before you push:

```bash
go build ./...
go vet ./...
gofmt -l .        # should print nothing
```

There is no test suite yet; contributions that add one are very welcome.

## Codebase layout

| Path | What lives there |
|---|---|
| `main.go` | wiring, env config |
| `internal/engine/` | the data plane: routing, TLS/ACME, streams, access lists, UPnP, GeoIP |
| `internal/store/` | SQLite persistence + validation (the typed-options contract) |
| `internal/admin/` | management REST API + auth (OIDC/LDAP/2FA/tokens) |
| `web/` | embedded admin UI (`index.html`, `app.js`, `app.css`, design tokens, Swagger) |
| `SPEC.md` / `ROADMAP.md` / `API.md` | design docs |

A new host/stream/access-list option typically touches: `store/` (field +
validation), `engine/` (apply it), `web/` (expose it), and `web/openapi.yaml`.

## Pull requests

- Fork, branch, and open a PR against `master`.
- Keep PRs focused — one feature or fix per PR.
- Describe the change and how you tested it. Screenshots help for UI changes.
- Match the surrounding code style; run `gofmt`.
- By submitting a PR you agree your contribution is licensed under the project's
  [MIT license](LICENSE).

## Bugs and ideas

Open an [issue](https://github.com/maferick/quicgate/issues). For **security**
problems, do **not** use issues — follow [SECURITY.md](SECURITY.md) instead.

Because this is a hobby project with one maintainer, responses may take a few
days. Thanks for your patience, and for helping make a small proxy manager
better.
