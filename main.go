// quicgate: a single-binary reverse proxy manager. NPM's workflow, a native
// Go engine (HTTP/1.1, HTTP/2, HTTP/3 via quic-go, ACME via certmagic), and
// every advanced option typed instead of free-text config.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"quicgate/internal/admin"
	"quicgate/internal/docker"
	"quicgate/internal/engine"
	"quicgate/internal/store"
)

// dockerEndpoints resolves the Docker hosts to watch. A JSON list in
// QG_DOCKER_ENDPOINTS or the docker_endpoints setting is authoritative when
// present; otherwise a single local endpoint is derived from the socket env.
func dockerEndpoints(st *store.Store) []docker.Endpoint {
	raw := os.Getenv("QG_DOCKER_ENDPOINTS")
	if strings.TrimSpace(raw) == "" {
		raw = st.GetSetting("docker_endpoints", "")
	}
	if strings.TrimSpace(raw) != "" {
		var eps []docker.Endpoint
		if err := json.Unmarshal([]byte(raw), &eps); err == nil && len(eps) > 0 {
			for i := range eps {
				if eps[i].Connect == "" {
					eps[i].Connect = "/var/run/docker.sock"
				}
				if eps[i].Address == "" {
					eps[i].Address = "127.0.0.1"
				}
				if eps[i].Name == "" {
					eps[i].Name = fmt.Sprintf("endpoint%d", i+1)
				}
			}
			return eps
		}
		log.Printf("docker: ignoring invalid docker_endpoints JSON, falling back to the local socket")
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

	eng := engine.New(engine.Config{
		HTTPAddr:   env("QG_HTTP", ":80"),
		HTTPSAddr:  env("QG_HTTPS", ":443"),
		DataDir:    dataDir,
		ACMEEmail:  os.Getenv("QG_ACME_EMAIL"),
		ACMEStage:  os.Getenv("QG_ACME_STAGING") == "1",
		DisableTLS: os.Getenv("QG_TLS") == "off",
		DisableH3:  os.Getenv("QG_H3") == "off",
		UPnP:       os.Getenv("QG_UPNP") == "1",
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
					if !h.Enabled {
						continue
					}
					for _, d := range h.Domains {
						m[strings.ToLower(d)] = true
					}
				}
				return m
			},
			Setting: st.GetSetting,
		})
		adm.SetDocker(dockerProvider)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
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
