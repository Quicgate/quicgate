// quicgate: a single-binary reverse proxy manager. NPM's workflow, a native
// Go engine (HTTP/1.1, HTTP/2, HTTP/3 via quic-go, ACME via certmagic), and
// every advanced option typed instead of free-text config.
package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"quicgate/internal/admin"
	"quicgate/internal/docker"
	"quicgate/internal/engine"
	"quicgate/internal/store"
)

// dockerEndpoints resolves the Docker hosts to watch. A JSON list in
// QG_DOCKER_ENDPOINTS or the docker_endpoints setting is authoritative when
// present; otherwise a single local endpoint is derived from the socket env.
// A list that does not parse or validate names no endpoint at all: it is
// logged and nothing is watched, rather than guessing at what was meant or
// quietly watching the local socket instead of the daemons that were named.
func dockerEndpoints(st *store.Store) []docker.Endpoint {
	raw := os.Getenv("QG_DOCKER_ENDPOINTS")
	if strings.TrimSpace(raw) == "" {
		raw = st.GetSetting("docker_endpoints", "")
	}
	if strings.TrimSpace(raw) != "" {
		eps, err := docker.ParseEndpoints(raw)
		if err != nil {
			log.Printf("docker: %v; no Docker host is watched until the list is fixed", err)
			return nil
		}
		return eps
	}
	return []docker.Endpoint{{
		Name:    "local",
		Connect: env("QG_DOCKER_SOCKET", "/var/run/docker.sock"),
		Address: env("QG_DOCKER_HOST_ADDR", "127.0.0.1"),
	}}
}

//go:embed web
var webEmbed embed.FS

// version is stamped at build time via -ldflags "-X main.version=...".
// Defaults to "dev" for `go run`/unstamped builds.
var version = "dev"

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	dataDir := env("QG_DATA", "./data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("data dir: %v", err)
	}

	st, err := store.Open(dataDir + "/quicgate.db")
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	// "quicgate -unseal" prepares a rollback to a version from before secrets
	// were sealed: it writes them back as plaintext and exits. Any later start
	// of this version seals them again.
	if len(os.Args) > 1 && os.Args[1] == "-unseal" {
		n, err := st.Unseal()
		if err != nil {
			log.Fatalf("unseal: %v", err)
		}
		log.Printf("unseal: %d secrets are stored in PLAINTEXT again, readable by older versions. Start the older version now; this version would seal them again.", n)
		return
	}
	if ss := st.SealStatus(); ss.Locked {
		log.Printf("quicgate: the secret store is LOCKED: %s", ss.Reason)
	} else {
		log.Printf("quicgate: secrets are sealed with key %s from %s", ss.KeyID, ss.Source)
	}

	eng := engine.New(engine.Config{
		HTTPAddr:   env("QG_HTTP", ":80"),
		HTTPSAddr:  env("QG_HTTPS", ":443"),
		DataDir:    dataDir,
		ACMEEmail:  os.Getenv("QG_ACME_EMAIL"),
		ACMEStage:  os.Getenv("QG_ACME_STAGING") == "1",
		DisableTLS: os.Getenv("QG_TLS") == "off",
		DisableH3:  os.Getenv("QG_H3") == "off",
		UPnP:       os.Getenv("QG_UPNP") == "1",
		AdminAddr:  env("QG_ADMIN", ":81"),
		Version:    version,
	}, st)
	log.Printf("quicgate %s starting", version)

	webFS, err := fs.Sub(webEmbed, "web")
	if err != nil {
		log.Fatalf("web assets: %v", err)
	}
	adm := admin.New(st, eng, webFS, dataDir)
	if err := adm.EnsureAdmin(); err != nil {
		log.Fatalf("admin seed: %v", err)
	}

	// Docker label provider (opt-in): derives hosts and streams from container
	// labels and merges them into the engine. Enabled with QG_DOCKER=1 or the
	// docker_enabled setting; the daemon socket must be mounted into the
	// container (read-only is sufficient, the provider only ever reads).
	var dockerProvider *docker.Provider
	if os.Getenv("QG_DOCKER") == "1" || st.GetSetting("docker_enabled", "") == "1" {
		dockerProvider = docker.NewProvider(docker.Options{
			Endpoints:     dockerEndpoints(st),
			DefaultDomain: os.Getenv("QG_DOCKER_DOMAIN"),
			LabelPrefix:   env("QG_DOCKER_LABEL_PREFIX", "quicgate"),
		}, docker.Hooks{
			Apply: eng.SetDockerRoutes,
			ResolveACL: func(name string) (int64, bool) {
				lists, err := st.ListAccessLists()
				if err != nil {
					return 0, false
				}
				for _, l := range lists {
					if strings.EqualFold(l.Name, name) {
						return l.ID, true
					}
				}
				return 0, false
			},
			ExistingDomains: func() map[string]bool {
				hosts, err := st.ListHosts()
				if err != nil {
					return nil
				}
				m := map[string]bool{}
				for _, h := range hosts {
					// A configured name is configured whether or not its host
					// is switched on: a container must not take it over while
					// the host is disabled.
					for _, d := range h.Domains {
						m[strings.ToLower(d)] = true
					}
				}
				return m
			},
			UsedPorts: func() map[int]bool {
				used := map[int]bool{}
				for _, p := range eng.ReservedPorts() {
					used[p] = true
				}
				streams, err := st.ListStreams()
				if err != nil {
					return used
				}
				for _, s := range streams {
					last := max(s.ListenPort, s.ListenPortEnd)
					for p := s.ListenPort; p <= last; p++ {
						used[p] = true
					}
				}
				return used
			},
			Setting: st.GetSetting,
		})
		adm.SetDocker(dockerProvider)
	}

	// SIGTERM is what `docker stop` and most service managers send; without it
	// the process died without shutting listeners down, releasing UPnP
	// mappings or flushing the access log.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if dockerProvider != nil {
		go dockerProvider.Run(ctx)
	}

	adminAddr := env("QG_ADMIN", ":81")
	adminSrv := &http.Server{Addr: adminAddr, Handler: adm.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("admin: ui listening on %s", adminAddr)
		if err := adminSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("admin listener: %v", err)
		}
	}()

	if err := eng.Run(ctx); err != nil {
		log.Fatalf("engine: %v", err)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = adminSrv.Shutdown(shutdownCtx)
}
