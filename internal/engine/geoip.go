package engine

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// geoDB wraps an optional MaxMind country database. If the file is absent,
// country rules simply never match (logged once at load).
type geoDB struct {
	mu      sync.RWMutex
	db      *maxminddb.Reader
	path    string
	loadErr string
}

func openGeoDB(path string) *geoDB {
	g := &geoDB{path: path}
	g.open()
	return g
}

// open (re)loads the database from g.path, replacing any currently open reader.
func (g *geoDB) open() {
	db, err := maxminddb.Open(g.path)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.db != nil {
		_ = g.db.Close()
		g.db = nil
	}
	if err != nil {
		g.loadErr = err.Error()
		log.Printf("engine: no GeoIP database at %s (country rules inactive): %v", g.path, err)
		return
	}
	g.db = db
	g.loadErr = ""
	log.Printf("engine: GeoIP database loaded from %s", g.path)
}

// GeoStatus reports whether the GeoIP database is present and loaded, plus a
// little metadata so the UI can confirm the file is the right one.
type GeoStatus struct {
	Loaded    bool   `json:"loaded"`
	Path      string `json:"path"`
	Type      string `json:"type,omitempty"`      // e.g. GeoLite2-Country
	BuildDate string `json:"buildDate,omitempty"` // database build date
	Nodes     uint   `json:"nodes,omitempty"`     // node count (rough size indicator)
	Error     string `json:"error,omitempty"`     // why it is not loaded
}

func (g *geoDB) status() GeoStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()
	s := GeoStatus{Path: g.path}
	if g.db == nil {
		s.Error = g.loadErr
		return s
	}
	s.Loaded = true
	m := g.db.Metadata
	s.Type = m.DatabaseType
	s.Nodes = m.NodeCount
	if m.BuildEpoch > 0 {
		s.BuildDate = time.Unix(int64(m.BuildEpoch), 0).UTC().Format("2006-01-02")
	}
	return s
}

// lookup resolves an IP to its country code (a test helper for the UI). It
// distinguishes an invalid IP and a missing database from a genuine no-match.
func (g *geoDB) lookup(ipStr string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", fmt.Errorf("not a valid IP address")
	}
	g.mu.RLock()
	loaded := g.db != nil
	g.mu.RUnlock()
	if !loaded {
		return "", fmt.Errorf("no GeoIP database loaded")
	}
	return g.country(ip), nil
}

// GeoIPStatus reports the GeoIP database state for the admin UI.
func (e *Engine) GeoIPStatus() GeoStatus { return e.geo.status() }

// GeoLookup resolves an IP to its country code (the UI's "is it working?" test).
func (e *Engine) GeoLookup(ip string) (string, error) { return e.geo.lookup(ip) }

// GeoIPReload re-opens the GeoIP database from disk (after the user drops the
// file in) and returns the resulting status, so no restart is needed.
func (e *Engine) GeoIPReload() GeoStatus {
	e.geo.open()
	return e.geo.status()
}

// country returns the ISO country code for an IP, or "" if unknown / no DB.
func (g *geoDB) country(ip net.IP) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.db == nil {
		return ""
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := g.db.Lookup(ip, &rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}
