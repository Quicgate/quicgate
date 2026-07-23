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
	"time"

	"quicgate/internal/admin"
	"quicgate/internal/engine"
	"quicgate/internal/store"
)

//go:embed web
var webEmbed embed.FS

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
		UPnP:       os.Getenv("QG_UPNP") == "1",
	}, st)

	webFS, err := fs.Sub(webEmbed, "web")
	if err != nil {
		log.Fatalf("web assets: %v", err)
	}
	adm := admin.New(st, eng, webFS)
	if err := adm.EnsureAdmin(); err != nil {
		log.Fatalf("admin seed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

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
