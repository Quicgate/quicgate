package admin

import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"quicgate/internal/engine"
	"quicgate/internal/store"
	"quicgate/internal/wg"
)

// Devices (with or without local addresses of their own), LAN policies and owners' sessions
// (SPEC-wireguard.md parts 2 and 3). As with sites, a device's private key
// never reaches quicgate, its preshared key leaves quicgate once, and no call
// returns a refresh token.

func (s *Server) registerVPN(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/wg/devices", s.auth(s.handleListWGDevices))
	mux.HandleFunc("POST /api/wg/devices", s.auth(s.handleCreateWGDevice))
	mux.HandleFunc("PUT /api/wg/devices/{id}/enabled", s.auth(s.handleEnableWGDevice))
	mux.HandleFunc("DELETE /api/wg/devices/{id}", s.auth(s.handleRevokeWGDevice))
	mux.HandleFunc("PUT /api/wg/devices/{id}/access", s.auth(s.handleSetWGDeviceAccess))
	mux.HandleFunc("POST /api/wg/breakglass", s.auth(s.handleCreateBreakGlass))
	mux.HandleFunc("GET /api/wg/policies", s.auth(s.handleListVPNPolicies))
	mux.HandleFunc("POST /api/wg/policies", s.auth(s.handleSaveVPNPolicy))
	mux.HandleFunc("PUT /api/wg/policies/{id}", s.auth(s.handleSaveVPNPolicy))
	mux.HandleFunc("DELETE /api/wg/policies/{id}", s.auth(s.handleDeleteVPNPolicy))
	mux.HandleFunc("GET /api/wg/sessions", s.auth(s.handleListVPNSessions))
	mux.HandleFunc("POST /api/wg/sessions/{id}/end", s.auth(s.handleEndVPNSession))
	mux.HandleFunc("GET /api/wg/blocked", s.auth(s.handleListVPNBlocked))
	mux.HandleFunc("POST /api/wg/owners/block", s.auth(s.handleBlockVPNOwner))
	mux.HandleFunc("POST /api/wg/owners/unblock", s.auth(s.handleUnblockVPNOwner))
	mux.HandleFunc("POST /api/wg/explain", s.auth(s.handleExplainRoute))
	mux.HandleFunc("POST /api/wg/server-key/reset", s.auth(s.handleResetWGServerKey))
}

func (s *Server) wgReady(w http.ResponseWriter) bool {
	if s.store.GetSetting("wg_enabled", "") != "1" || s.engine.WGStatus().PublicKey == "" {
		writeErr(w, http.StatusBadRequest, "switch WireGuard on first: a device's configuration needs this server's public key")
		return false
	}
	return true
}

func (s *Server) handleListWGDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.store.ListWGDevices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range devices {
		devices[i].PresharedKey = ""
	}
	writeJSON(w, http.StatusOK, devices)
}

// createDevice validates the key, makes the preshared key, stores the device
// and reloads. The answer carries the preshared key, this once.
func (s *Server) createDevice(w http.ResponseWriter, r *http.Request, d *store.WGDevice) {
	d.PublicKey = strings.TrimSpace(d.PublicKey)
	if err := wg.ValidKey(d.PublicKey); err != nil {
		writeErr(w, http.StatusBadRequest, "public key: "+err.Error())
		return
	}
	if d.PublicKey == s.engine.WGStatus().PublicKey {
		writeErr(w, http.StatusBadRequest, "that is this server's own public key")
		return
	}
	_, tunnel, _, err := engine.WGSettings(s.store)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	psk, err := wg.NewPresharedKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.ID, d.Address, d.RevokedAt, d.Enabled = 0, "", "", true
	if err := s.store.CreateWGDevice(d, tunnel, psk, 0); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	d.PresharedKey = psk
	writeJSON(w, http.StatusCreated, d)
}

// deviceAccess is the part of a request that says which addresses on the
// local network an admin's device may reach, and what it takes to say so.
type deviceAccess struct {
	Routes       []store.VPNRoute
	ExpiresAt    string
	NeverExpires bool
	Password     string
	Code         string
}

// check validates the routes and the end date, and returns the end date as it
// is stored. Local addresses come with an end date unless the admin says in
// so many words that there is none; without addresses there is nothing to end.
func (a *deviceAccess) check() (expires string, err error) {
	for i := range a.Routes {
		if err := a.Routes[i].Validate(); err != nil {
			return "", err
		}
	}
	if len(a.Routes) == 0 {
		if a.ExpiresAt != "" || a.NeverExpires {
			return "", errors.New("an end date goes with addresses on the local network: name at least one, or leave the end date out")
		}
		return "", nil
	}
	if a.NeverExpires {
		return "", nil
	}
	t, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil || !t.After(time.Now()) {
		return "", errors.New("give an end date in the future, or say explicitly that the device never expires")
	}
	return t.UTC().Format(time.RFC3339), nil
}

// confirmLocalAccess is the price of giving a device addresses on the local
// network without anybody logging in behind it (S33), and of changing them
// later: the admin's password and a two-factor code, on an account that has
// two-factor on. It writes the refusal itself and reports whether to go on.
func (s *Server) confirmLocalAccess(w http.ResponseWriter, r *http.Request, password, code string) bool {
	sess := r.Context().Value(sessionKey).(session)
	u, status, msg := s.reauthenticate(sess, password)
	if status != 0 {
		writeErr(w, status, msg)
		return false
	}
	if u.TOTPSecret == "" {
		writeErr(w, http.StatusBadRequest, "local network access for a device needs two-factor authentication on this account: switch it on first")
		return false
	}
	if !s.verifyTOTP(u.ID, u.TOTPLast, u.TOTPSecret, code) {
		// A stolen session with the password is one guess of six digits away
		// from a device on the local network: counted like a failed login.
		s.codes.fail(accountKey(u.Email))
		writeErr(w, http.StatusUnauthorized, "the two-factor code does not match")
		return false
	}
	return true
}

// handleCreateWGDevice adds a device of the admin's. Without routes it
// reaches quicgate's hosts in the tunnel and nothing else. With routes it
// also reaches those addresses on the local network, with no single sign-on
// behind it, so that costs the password, a two-factor code and an end date
// (see confirmLocalAccess).
func (s *Server) handleCreateWGDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, PublicKey string
		deviceAccess
	}
	if err := decodeStrict(w, r, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	s.createAdminDevice(w, r, in.Name, in.PublicKey, &in.deviceAccess)
}

func (s *Server) createAdminDevice(w http.ResponseWriter, r *http.Request, name, publicKey string, a *deviceAccess) {
	if !s.wgReady(w) {
		return
	}
	// What can be checked without the second factor is checked first: a code
	// is good once, and a mistake in the form should not use it up.
	expires, err := a.check()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(a.Routes) > 0 && !s.confirmLocalAccess(w, r, a.Password, a.Code) {
		return
	}
	s.createDevice(w, r, &store.WGDevice{Name: name, Kind: "admin", PublicKey: publicKey, Routes: a.Routes, ExpiresAt: expires})
}

// handleSetWGDeviceAccess changes which local addresses a device of the
// admin's may reach, and its end date. It always costs the confirmation, also
// when it only takes addresses away: one call, one rule, and nothing a stolen
// session can do to a device by "editing" it. The reload closes the flows the
// device may no longer have.
func (s *Server) handleSetWGDeviceAccess(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in deviceAccess
	if err := decodeStrict(w, r, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	d, err := s.store.GetWGDevice(id)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && d.RevokedAt != "") {
		writeErr(w, http.StatusNotFound, "device not found, or revoked")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if d.Kind != "admin" && d.Kind != "breakglass" {
		writeErr(w, http.StatusBadRequest, "what a person's device may reach follows from the rules for that person: it has no addresses of its own")
		return
	}
	expires, err := in.check()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.confirmLocalAccess(w, r, in.Password, in.Code) {
		return
	}
	if err := s.store.SetWGDeviceAccess(id, in.Routes, expires); errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "device not found, or revoked")
		return
	} else if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	d, err = s.store.GetWGDevice(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.PresharedKey = ""
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleEnableWGDevice(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct{ Enabled bool }
	if err := decodeStrict(w, r, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	if err := s.store.SetWGDeviceEnabled(id, in.Enabled); errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "device not found, or revoked")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevokeWGDevice(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.RevokeWGDevice(id, nil); errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "device not found, or revoked already")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCreateBreakGlass is the older call for a device with local addresses
// and no single sign-on behind it (S33). It is POST /api/wg/devices with
// routes that may not be left out: the same checks, the same device (kind
// admin). The cap of two is gone with the separate kind.
func (s *Server) handleCreateBreakGlass(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, PublicKey string
		deviceAccess
	}
	if err := decodeJSON(w, r, &in, maxJSONBody, false); err != nil {
		writeBodyErr(w, err)
		return
	}
	if len(in.Routes) == 0 {
		writeErr(w, http.StatusBadRequest, "name the addresses on the local network the device may reach")
		return
	}
	s.createAdminDevice(w, r, in.Name, in.PublicKey, &in.deviceAccess)
}

func (s *Server) handleListVPNPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListVPNPolicies()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *Server) handleSaveVPNPolicy(w http.ResponseWriter, r *http.Request) {
	var p store.VPNPolicy
	if err := decodeStrict(w, r, &p); err != nil {
		writeBodyErr(w, err)
		return
	}
	p.ID = 0
	if r.Method == http.MethodPut {
		id, err := pathID(r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid id")
			return
		}
		p.ID = id
	}
	if err := s.store.SaveVPNPolicy(&p); errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "policy not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteVPNPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteVPNPolicy(id); errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "policy not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListVPNSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.ListVPNSessions()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sessions) // the refresh token has no JSON form
}

// handleEndVPNSession ends a person's lease now. Their devices leave the
// endpoint with the reload; a fresh login at the portal brings them back.
func (s *Server) handleEndVPNSession(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.EndVPNSession(id, "ended", 0); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListVPNBlocked(w http.ResponseWriter, r *http.Request) {
	blocked, err := s.store.ListVPNBlocked()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, blocked)
}

// handleBlockVPNOwner blocks a person from the VPN. Unlike an ended session,
// a login does not undo it (S43).
func (s *Server) handleBlockVPNOwner(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Provider   int64
		Sub, Email string
	}
	if err := decodeStrict(w, r, &in); err != nil || in.Provider <= 0 || in.Sub == "" {
		writeErr(w, http.StatusBadRequest, "give the identity provider and the person's subject id")
		return
	}
	if err := s.store.BlockVPNOwner(in.Provider, in.Sub, in.Email); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUnblockVPNOwner(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Provider int64
		Sub      string
	}
	if err := decodeStrict(w, r, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	if err := s.store.UnblockVPNOwner(in.Provider, in.Sub); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleExplainRoute says whether routes would let a device reach a
// destination on this machine's network, and why not: the policy editor's way
// to test a policy without a device.
func (s *Server) handleExplainRoute(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Routes      []store.VPNRoute
		Proto, Dest string
	}
	if err := decodeStrict(w, r, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	for i := range in.Routes {
		if err := in.Routes[i].Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	answer, err := s.engine.ExplainRoute(in.Routes, in.Proto, in.Dest)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"answer": answer})
}

// vpnOverview is what the overview's Attention list says about the VPN.
func (s *Server) vpnOverview() map[string]any {
	st := s.engine.WGStatus()
	out := map[string]any{"enabled": st.Enabled, "running": st.Running, "error": st.Error, "lanAccess": st.LANAccess,
		"flowLogDropped": s.engine.FlowLogDropped(), "flowLogError": s.engine.FlowLogError(), "localAccessDevices": 0, "localAccessNoExpiry": 0}
	devices, err := s.store.ListWGDevices()
	if err != nil {
		return out
	}
	n, never := 0, 0
	// Devices that reach the local network with nobody logged in behind them:
	// the admin's own with routes, under either name of the kind.
	for _, d := range devices {
		if (d.Kind == "admin" || d.Kind == "breakglass") && d.RevokedAt == "" && len(d.Routes) > 0 {
			n++
			if d.ExpiresAt == "" {
				never++
			}
		}
	}
	out["localAccessDevices"], out["localAccessNoExpiry"] = n, never
	// The names before 1.20.0, kept for API clients that read them.
	out["breakGlass"], out["breakGlassNoExpiry"] = n, never
	return out
}

// inBridgeContainer guesses that quicgate runs in a container on a bridge
// network: there its published ports live on an address it cannot see. The
// guess is an aid, never a guarantee (S48).
func inBridgeContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return false
	}
	return len(ownNetworks()) <= 1
}

// checkVPNSettings validates the Release C settings in a settings update.
func (s *Server) checkVPNSettings(body map[string]string) error {
	ranges := map[string][2]int{"wg_lease_minutes": {2, 1440}, "wg_outage_grace_minutes": {0, 60}, "wg_session_days": {1, 90},
		"wg_auth_max_age": {60, 86400}, "wg_devices_per_user": {1, 50}}
	for key, lim := range ranges {
		if v, ok := body[key]; ok && v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < lim[0] || n > lim[1] {
				return errors.New(key + " must be between " + strconv.Itoa(lim[0]) + " and " + strconv.Itoa(lim[1]))
			}
		}
	}
	protected, hasProtected := body["wg_protected_endpoints"]
	if hasProtected {
		if _, _, err := engine.ParseProtectedEndpoints(protected); err != nil {
			return errors.New("wg_protected_endpoints: " + err.Error())
		}
	} else {
		protected = s.store.GetSetting("wg_protected_endpoints", "")
	}
	if body["wg_lan_access"] == "1" && inBridgeContainer() {
		waived := body["wg_no_published_aliases"] == "1" || s.store.GetSetting("wg_no_published_aliases", "") == "1"
		if strings.TrimSpace(protected) == "" && !waived {
			return errors.New("quicgate seems to run in a container on a bridge network, where its published ports live on addresses it cannot see. List the Docker host's addresses under protected endpoints, or confirm that no quicgate port is published anywhere a policy can reach, before switching LAN access on")
		}
	}
	return nil
}

// handleResetWGServerKey throws the stored server key away, so the next reload
// makes a new one. It exists for one situation: the stored key cannot be opened
// (a restore under another sealing key) and the original sealing key is gone.
// Every site's and device's configuration names the old public key and stops
// working, so it takes the admin's password and only works while the key is
// in fact unreadable; a readable key is never reset this way.
func (s *Server) handleResetWGServerKey(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessionKey).(session)
	var in struct{ Password string }
	if err := decodeJSON(w, r, &in, maxLoginBody, false); err != nil {
		writeBodyErr(w, err)
		return
	}
	if _, status, msg := s.reauthenticate(sess, in.Password); status != 0 {
		writeErr(w, status, msg)
		return
	}
	if _, state := s.store.SecretSetting("wg_private_key"); state != store.SecretUnreadable {
		writeErr(w, http.StatusConflict, "the server key can be read: there is nothing to reset")
		return
	}
	if err := s.store.DeleteSetting("wg_private_key"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "the key was reset, but applying it failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
