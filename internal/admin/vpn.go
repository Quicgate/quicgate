package admin

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"

	"quicgate/internal/engine"
	"quicgate/internal/store"
	"quicgate/internal/wg"
)

// Devices, LAN policies, owners' sessions and break-glass devices
// (SPEC-wireguard.md parts 2 and 3). As with sites, a device's private key
// never reaches quicgate, its preshared key leaves quicgate once, and no call
// returns a refresh token.

const maxBreakGlass = 2

func (s *Server) registerVPN(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/wg/devices", s.auth(s.handleListWGDevices))
	mux.HandleFunc("POST /api/wg/devices", s.auth(s.handleCreateWGDevice))
	mux.HandleFunc("PUT /api/wg/devices/{id}/enabled", s.auth(s.handleEnableWGDevice))
	mux.HandleFunc("DELETE /api/wg/devices/{id}", s.auth(s.handleRevokeWGDevice))
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

func (s *Server) handleCreateWGDevice(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, PublicKey string }
	if err := decodeStrict(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.wgReady(w) {
		return
	}
	// An admin's device reaches quicgate's hosts in the tunnel and nothing
	// else. LAN access takes a person's login, or a break-glass device.
	s.createDevice(w, r, &store.WGDevice{Name: in.Name, Kind: "admin", PublicKey: in.PublicKey})
}

func (s *Server) handleEnableWGDevice(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct{ Enabled bool }
	if err := decodeStrict(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
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

// handleCreateBreakGlass issues a device with LAN routes of its own and no
// single sign-on behind it (S33): the way back in when the identity provider
// itself is what broke. It takes the admin's password and a TOTP code, the
// account must have two-factor on, there are at most two, and an expiry is
// required unless the admin says in so many words that it shall not expire.
func (s *Server) handleCreateBreakGlass(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessionKey).(session)
	var in struct {
		Name, PublicKey, Password, Code, ExpiresAt string
		Routes                                     []store.VPNRoute
		NeverExpires                               bool
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !s.wgReady(w) {
		return
	}
	u, status, msg := s.reauthenticate(sess, in.Password)
	if status != 0 {
		writeErr(w, status, msg)
		return
	}
	if u.TOTPSecret == "" {
		writeErr(w, http.StatusBadRequest, "a break-glass device needs two-factor authentication on this account: switch it on first")
		return
	}
	if !totp.Validate(in.Code, u.TOTPSecret) {
		writeErr(w, http.StatusUnauthorized, "the two-factor code does not match")
		return
	}
	if len(in.Routes) == 0 {
		writeErr(w, http.StatusBadRequest, "a break-glass device needs the routes it may reach")
		return
	}
	expires := ""
	if !in.NeverExpires {
		t, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil || !t.After(time.Now()) {
			writeErr(w, http.StatusBadRequest, "give an expiry in the future, or say explicitly that the device never expires")
			return
		}
		expires = t.UTC().Format(time.RFC3339)
	}
	existing, err := s.store.ListWGDevices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	n := 0
	for _, d := range existing {
		if d.Kind == "breakglass" && d.RevokedAt == "" {
			n++
		}
	}
	if n >= maxBreakGlass {
		writeErr(w, http.StatusBadRequest, "there are two break-glass devices already: revoke one first")
		return
	}
	s.createDevice(w, r, &store.WGDevice{Name: in.Name, Kind: "breakglass", PublicKey: in.PublicKey, Routes: in.Routes, ExpiresAt: expires})
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
	if err := decodeStrict(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
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
	if err := decodeStrict(r, &in); err != nil || in.Provider <= 0 || in.Sub == "" {
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
	if err := decodeStrict(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
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
	if err := decodeStrict(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
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
		"flowLogDropped": s.engine.FlowLogDropped(), "breakGlass": 0, "breakGlassNoExpiry": 0}
	devices, err := s.store.ListWGDevices()
	if err != nil {
		return out
	}
	n, never := 0, 0
	for _, d := range devices {
		if d.Kind == "breakglass" && d.RevokedAt == "" {
			n++
			if d.ExpiresAt == "" {
				never++
			}
		}
	}
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
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
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
