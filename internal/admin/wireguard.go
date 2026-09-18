package admin

import (
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"quicgate/internal/engine"
	"quicgate/internal/store"
	"quicgate/internal/wg"
)

// WireGuard sites (SPEC-wireguard.md, part 1). A site's private key never
// reaches quicgate: the admin's browser generates the keypair and sends the
// public key (S21). quicgate generates the preshared key and returns it
// exactly once, in the answer to the create call (S37); after that no call
// returns it, and none ever returns the server's private key.

func (s *Server) registerWireGuard(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/wg/status", s.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.engine.WGStatus())
	}))
	mux.HandleFunc("GET /api/wg/sites", s.auth(s.handleListWGSites))
	mux.HandleFunc("POST /api/wg/sites", s.auth(s.handleCreateWGSite))
	mux.HandleFunc("PUT /api/wg/sites/{id}", s.auth(s.handleUpdateWGSite))
	mux.HandleFunc("DELETE /api/wg/sites/{id}", s.auth(s.handleDeleteWGSite))
}

// checkWGSettings validates the WireGuard settings in a settings update.
func (s *Server) checkWGSettings(body map[string]string) error {
	if v, ok := body["wg_port"]; ok && v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return errors.New("wg_port must be a port number")
		}
		for _, reserved := range []string{s.engineHTTPPort(), s.engineHTTPSPort()} {
			if reserved == v {
				return errors.New("wg_port is taken by the proxy itself")
			}
		}
	}
	if v, ok := body["wg_network"]; ok && v != "" {
		p, err := netip.ParsePrefix(v)
		if err != nil || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 29 {
			return errors.New("wg_network must be an IPv4 prefix between /16 and /29, like 10.77.0.0/24")
		}
		if cur := s.store.GetSetting("wg_network", ""); p.Masked().String() != cur {
			sites, err := s.store.ListWGSites()
			if err != nil {
				return err
			}
			// Every site has an address in the network and a configuration that
			// names it. Moving the network would silently break all of them.
			if len(sites) > 0 && !(cur == "" && p.Masked().String() == "10.77.0.0/24") {
				return errors.New("the tunnel network cannot change while sites exist: their addresses and configurations depend on it")
			}
		}
		body["wg_network"] = p.Masked().String()
	}
	if v, ok := body["wg_endpoint"]; ok && v != "" {
		host, port, err := net.SplitHostPort(v)
		if err != nil || host == "" || port == "" {
			return errors.New("wg_endpoint must look like vpn.example.com:51820")
		}
	}
	return nil
}

func (s *Server) engineHTTPPort() string  { return portString(s.engine.ReservedPorts(), 0) }
func (s *Server) engineHTTPSPort() string { return portString(s.engine.ReservedPorts(), 1) }

func portString(ports []int, i int) string {
	if i < len(ports) {
		return strconv.Itoa(ports[i])
	}
	return ""
}

// ownNetworks lists the IPv4 subnets on this machine's interfaces, so a site
// that claims one of them needs a deliberate confirmation.
func ownNetworks() []netip.Prefix {
	var out []netip.Prefix
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok || !ip.Unmap().Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		ones, _ := n.Mask.Size()
		if p, err := ip.Unmap().Prefix(ones); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func toWGSite(s store.WGSite) (wg.Site, error) {
	out := wg.Site{ID: s.ID, Name: strings.TrimSpace(s.Name), PublicKey: strings.TrimSpace(s.PublicKey),
		PresharedKey: s.PresharedKey, Endpoint: strings.TrimSpace(s.Endpoint), Keepalive: s.Keepalive, Enabled: s.Enabled}
	if s.Address != "" {
		a, err := netip.ParseAddr(s.Address)
		if err != nil {
			return out, errors.New("address: " + err.Error())
		}
		out.Address = a
	}
	for _, n := range s.Networks {
		p, err := netip.ParsePrefix(strings.TrimSpace(n))
		if err != nil {
			return out, errors.New("network " + n + ": not a prefix like 192.168.50.0/24")
		}
		out.Networks = append(out.Networks, p.Masked())
	}
	return out, nil
}

// validateWGSite checks a site against everything that exists. The address is
// not the caller's to choose, so on create a placeholder stands in for it.
func (s *Server) validateWGSite(in store.WGSite, psk string) error {
	_, tunnel, _, err := engine.WGSettings(s.store)
	if err != nil {
		return err
	}
	if in.Endpoint != "" {
		host, port, err := net.SplitHostPort(strings.TrimSpace(in.Endpoint))
		if err != nil || host == "" || port == "" {
			return errors.New("endpoint must look like host:port")
		}
	}
	site, err := toWGSite(in)
	if err != nil {
		return err
	}
	site.PresharedKey = psk
	stored, err := s.store.ListWGSites()
	if err != nil {
		return err
	}
	var others []wg.Site
	for _, o := range stored {
		if o.ID == in.ID {
			site.Address, _ = netip.ParseAddr(o.Address)
			continue
		}
		other, err := toWGSite(o)
		if err != nil {
			continue
		}
		others = append(others, other)
	}
	if !site.Address.IsValid() {
		// A new site: any free host address will do for the checks.
		site.Address = wg.TunnelAddress(tunnel).Next()
		for taken := true; taken; {
			taken = false
			for _, o := range others {
				if o.Address == site.Address {
					site.Address, taken = site.Address.Next(), true
				}
			}
		}
	}
	return wg.ValidateSite(site, tunnel, s.engine.WGStatus().PublicKey, others, ownNetworks(), in.AllowOwnOverlap)
}

func blankPSK(sites []store.WGSite) []store.WGSite {
	for i := range sites {
		sites[i].PresharedKey = ""
	}
	return sites
}

func (s *Server) handleListWGSites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.store.ListWGSites()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, blankPSK(sites))
}

func (s *Server) handleCreateWGSite(w http.ResponseWriter, r *http.Request) {
	var in store.WGSite
	if err := decodeStrict(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	in.ID, in.Address, in.PresharedKey = 0, "", ""
	if s.store.GetSetting("wg_enabled", "") != "1" || s.engine.WGStatus().PublicKey == "" {
		writeErr(w, http.StatusBadRequest, "switch WireGuard on first: a site's configuration needs this server's public key")
		return
	}
	psk, err := wg.NewPresharedKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.validateWGSite(in, psk); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, tunnel, _, err := engine.WGSettings(s.store)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateWGSite(&in, tunnel, psk); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	// The one time the preshared key leaves quicgate.
	in.PresharedKey = psk
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) handleUpdateWGSite(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	cur, err := s.store.GetWGSite(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var in store.WGSite
	if err := decodeStrict(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	in.ID, in.Address = id, cur.Address
	psk := cur.PresharedKey
	if psk == "" {
		// Locked store: the key cannot be read, and the site is validated with
		// a stand-in. What is stored is not touched by an update.
		if psk, err = wg.NewPresharedKey(); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := s.validateWGSite(in, psk); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdateWGSite(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	in.PresharedKey = ""
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) handleDeleteWGSite(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	err = s.store.DeleteWGSite(id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, http.StatusNotFound, "site not found")
		return
	case errors.Is(err, store.ErrWGSiteInUse):
		writeErr(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
