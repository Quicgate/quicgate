package engine

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway1"
)

const upnpRenewInterval = 30 * time.Minute

// PortMapping is one router forward quicgate wants for itself.
type PortMapping struct {
	Proto string // TCP | UDP
	Port  uint16
}

func (p PortMapping) key() string { return fmt.Sprintf("%s:%d", p.Proto, p.Port) }

// UPnPManager keeps FRITZ!Box (IGD) port forwards in sync with the ports the
// engine and its streams listen on. Mappings are leased and re-added on a
// timer, so they self-heal after a router reboot and expire after a crash.
type UPnPManager struct {
	mu      sync.Mutex
	client  *internetgateway1.WANIPConnection1
	localIP string
	lease   uint32
	mapped  map[string]bool
	desired []PortMapping
	done    chan struct{}
}

func NewUPnPManager(leaseSeconds uint32) *UPnPManager {
	m := &UPnPManager{lease: leaseSeconds, mapped: map[string]bool{}, done: make(chan struct{})}
	go m.renewLoop()
	return m
}

func (m *UPnPManager) renewLoop() {
	t := time.NewTicker(upnpRenewInterval)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			m.mu.Lock()
			desired := append([]PortMapping(nil), m.desired...)
			m.mu.Unlock()
			m.Sync(desired)
		}
	}
}

// ensureClient discovers the IGD once and derives our LAN IP toward it.
func (m *UPnPManager) ensureClient() error {
	if m.client != nil {
		return nil
	}
	clients, _, err := internetgateway1.NewWANIPConnection1Clients()
	if err != nil {
		return fmt.Errorf("igd discovery: %w", err)
	}
	if len(clients) == 0 {
		return fmt.Errorf("no UPnP internet gateway found")
	}
	c := clients[0]
	loc := c.ServiceClient.Location
	conn, err := net.Dial("udp", loc.Host)
	if err != nil {
		return fmt.Errorf("derive local ip: %w", err)
	}
	localIP, _, _ := net.SplitHostPort(conn.LocalAddr().String())
	conn.Close()
	m.client = c
	m.localIP = localIP
	if ip, err := c.GetExternalIPAddress(); err == nil {
		log.Printf("upnp: gateway %s, local %s, external %s", loc.Host, localIP, ip)
	}
	return nil
}

// Sync makes the router's mappings match desired: adds missing, removes stale.
// Failures on individual ports (e.g. a port still forwarded to another host)
// are logged and skipped, never fatal.
func (m *UPnPManager) Sync(desired []PortMapping) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.desired = append([]PortMapping(nil), desired...)
	if err := m.ensureClient(); err != nil {
		log.Printf("upnp: %v", err)
		return
	}
	want := map[string]PortMapping{}
	for _, p := range desired {
		want[p.key()] = p
	}
	for key := range m.mapped {
		if _, ok := want[key]; ok {
			continue
		}
		parts := strings.SplitN(key, ":", 2)
		var port uint16
		fmt.Sscanf(parts[1], "%d", &port)
		if err := m.client.DeletePortMapping("", port, parts[0]); err != nil {
			log.Printf("upnp: unmap %s: %v", key, err)
		} else {
			log.Printf("upnp: unmapped %s", key)
		}
		delete(m.mapped, key)
	}
	for key, p := range want {
		err := m.client.AddPortMapping("", p.Port, p.Proto, p.Port, m.localIP, true, "quicgate", m.lease)
		if err != nil && strings.Contains(err.Error(), "725") {
			// Router only supports permanent leases.
			err = m.client.AddPortMapping("", p.Port, p.Proto, p.Port, m.localIP, true, "quicgate", 0)
		}
		if err != nil {
			if !m.mapped[key] {
				log.Printf("upnp: map %s -> %s failed (in use elsewhere?): %v", key, m.localIP, err)
			}
			delete(m.mapped, key)
			continue
		}
		if !m.mapped[key] {
			log.Printf("upnp: mapped %s -> %s:%d", key, m.localIP, p.Port)
		}
		m.mapped[key] = true
	}
}

// Close removes every mapping this manager added.
func (m *UPnPManager) Close() {
	close(m.done)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client == nil {
		return
	}
	for key := range m.mapped {
		parts := strings.SplitN(key, ":", 2)
		var port uint16
		fmt.Sscanf(parts[1], "%d", &port)
		if err := m.client.DeletePortMapping("", port, parts[0]); err != nil {
			log.Printf("upnp: cleanup %s: %v", key, err)
		}
		delete(m.mapped, key)
	}
	log.Printf("upnp: all mappings removed")
}
