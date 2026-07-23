package engine

import (
	"log"
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// geoDB wraps an optional MaxMind country database. If the file is absent,
// country rules simply never match (logged once at load).
type geoDB struct {
	mu sync.RWMutex
	db *maxminddb.Reader
}

func openGeoDB(path string) *geoDB {
	g := &geoDB{}
	if db, err := maxminddb.Open(path); err == nil {
		g.db = db
		log.Printf("engine: GeoIP database loaded from %s", path)
	} else {
		log.Printf("engine: no GeoIP database at %s (country rules inactive): %v", path, err)
	}
	return g
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
