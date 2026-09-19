package engine

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"quicgate/internal/store"
	"quicgate/internal/wg"
)

// The VPN portal (SPEC-wireguard.md part 3): where a person logs in with the
// identity provider to enrol devices, and to get them back when their
// authorization ran out. It is a surface of its own (S22): its handlers live
// under /.qg/vpn/ on the portal host only, it shares no session, cookie or
// token with the admin API, and it can do four things: show my devices, add
// one, revoke one, log in again.
//
// What "mandatory single sign-on" means here (S24): a device can only be
// enrolled after a fresh login; it is part of the WireGuard endpoint only
// while its owner holds an authorization lease; and a lease is only renewed
// on positive evidence from the provider (S45). Stock WireGuard has no login
// of its own, so between renewals the device's key is the credential.

//go:embed portal/*
var portalFS embed.FS

const (
	portalCookie   = "qg_vpn"
	portalTxCookie = "qg_vpn_tx"
	portalIdle     = 30 * time.Minute
	portalTxTTL    = 10 * time.Minute
	authTimeSkew   = 60 * time.Second
)

// portalSession is a browser's login at the portal. It lives in memory and is
// short: it only serves the page. The owner's lease is a different thing, and
// lives in the database.
type portalSession struct {
	provider int64
	sub      string
	email    string
	expires  time.Time
	// authTime is when the person authenticated at the identity provider, as
	// the provider stated it at login. Adding a device takes a fresh one
	// (QG-08): the page's session slides with use and says nothing about that.
	authTime time.Time
}

type portalState struct {
	mu       sync.Mutex
	sessions map[string]portalSession
	renewing sync.Map // session id -> struct{}: one renewal at a time (S44)
	lastLive string   // who held a lease at the last tick, to notice expiry
}

func newPortalState() *portalState { return &portalState{sessions: map[string]portalSession{}} }

func (p *portalState) create(s portalSession) string {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	id := base64.RawURLEncoding.EncodeToString(raw)
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, v := range p.sessions {
		if now.After(v.expires) {
			delete(p.sessions, k)
		}
	}
	p.sessions[id] = s
	return id
}

func (p *portalState) get(id string) (portalSession, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[id]
	if !ok || time.Now().After(s.expires) {
		delete(p.sessions, id)
		return portalSession{}, false
	}
	s.expires = time.Now().Add(portalIdle)
	p.sessions[id] = s
	return s, true
}

func (p *portalState) drop(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, id)
}

// portalTx is the login in flight, in a signed cookie of its own purpose.
type portalTx struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Host     string `json:"h"`
	Expiry   int64  `json:"x"`
}

func randomToken() string {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (e *Engine) vpnIntSetting(key string, def int) int {
	if n, err := strconv.Atoi(e.store.GetSetting(key, "")); err == nil && n >= 0 {
		return n
	}
	return def
}

func requestOrigin(r *http.Request) string {
	scheme := "http"
	if portalEncrypted(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// portalEncrypted reports whether the browser's connection is encrypted: TLS
// here, or TLS at a trusted proxy in front of quicgate that says so. The
// header alone is not believed, because anybody can send it.
func portalEncrypted(r *http.Request) bool {
	return r.TLS != nil || (viaTrustedProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
}

// portalHandler serves one portal host.
func (e *Engine) portalHandler(h store.Host) http.Handler {
	opts := *h.Options.Portal
	signer := &oidcGate{engine: &engineOIDC{secret: e.oidcSecret, discover: e.oidcDiscover}}
	mux := http.NewServeMux()

	static := func(name, ctype string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			data, err := portalFS.ReadFile("portal/" + name)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", ctype)
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write(data)
		}
	}
	mux.HandleFunc("GET /{$}", static("portal.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /.qg/vpn/portal.js", static("portal.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /.qg/vpn/portal.css", static("portal.css", "text/css; charset=utf-8"))

	provider := func() (store.OIDCProvider, bool) {
		all, err := e.store.ListOIDCProviders()
		if err != nil {
			return store.OIDCProvider{}, false
		}
		for _, p := range all {
			if p.ID == opts.ProviderID {
				return p, true
			}
		}
		return store.OIDCProvider{}, false
	}
	oauthConfig := func(r *http.Request, p store.OIDCProvider, disc *oidc.Provider) oauth2.Config {
		scopes := map[string]bool{oidc.ScopeOpenID: true, "email": true, "profile": true, oidc.ScopeOfflineAccess: true}
		for _, s := range p.Scopes {
			scopes[s] = true
		}
		var list []string
		for s := range scopes {
			list = append(list, s)
		}
		sort.Strings(list)
		return oauth2.Config{ClientID: p.ClientID, ClientSecret: p.ClientSecret, Endpoint: disc.Endpoint(),
			RedirectURL: requestOrigin(r) + "/.qg/vpn/callback", Scopes: list}
	}
	setCookie := func(w http.ResponseWriter, r *http.Request, name, value string, maxAge int, sameSite http.SameSite) {
		// Always Secure. The one exception is a development instance that was
		// started without TLS altogether, where there is no HTTPS to send it on.
		http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: portalEncrypted(r) || !e.cfg.DisableTLS,
			SameSite: sameSite, MaxAge: maxAge}) // no Domain: host-only
	}

	mux.HandleFunc("GET /.qg/vpn/login", func(w http.ResponseWriter, r *http.Request) {
		p, ok := provider()
		if !ok {
			http.Error(w, "the portal's identity provider is not configured", http.StatusServiceUnavailable)
			return
		}
		disc, err := e.oidcDiscover(r, p)
		if err != nil {
			http.Error(w, "the identity provider cannot be reached", http.StatusBadGateway)
			return
		}
		tx := portalTx{State: randomToken(), Nonce: randomToken(), Verifier: oauth2.GenerateVerifier(), Host: requestHostname(r), Expiry: time.Now().Add(portalTxTTL).Unix()}
		payload, _ := json.Marshal(tx)
		setCookie(w, r, portalTxCookie, signer.sign(portalTxCookie, payload), int(portalTxTTL.Seconds()), http.SameSiteLaxMode)
		cfg := oauthConfig(r, p, disc)
		// max_age asks the provider for an authentication no older than this.
		// The callback checks auth_time itself: a redirect that an existing
		// browser session answers silently is not a fresh login (S54).
		maxAge := e.vpnIntSetting("wg_auth_max_age", 900)
		http.Redirect(w, r, cfg.AuthCodeURL(tx.State, oauth2.S256ChallengeOption(tx.Verifier), oidc.Nonce(tx.Nonce),
			oauth2.SetAuthURLParam("max_age", strconv.Itoa(maxAge))), http.StatusFound)
	})

	fail := func(w http.ResponseWriter, status int, msg string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>VPN portal</title><link rel="stylesheet" href="/.qg/vpn/portal.css"><body><main class="notice"><h1>Not logged in</h1><p>%s</p><p><a href="/">Back to the portal</a></p>`, htmlEscape(msg))
	}

	mux.HandleFunc("GET /.qg/vpn/callback", func(w http.ResponseWriter, r *http.Request) {
		var tx portalTx
		ck, err := r.Cookie(portalTxCookie)
		// The transaction cookie is used once, whatever happens next.
		setCookie(w, r, portalTxCookie, "", -1, http.SameSiteLaxMode)
		if err != nil || !signer.verify(portalTxCookie, ck.Value, &tx) || time.Now().Unix() > tx.Expiry || tx.Host != requestHostname(r) ||
			subtle.ConstantTimeCompare([]byte(tx.State), []byte(r.URL.Query().Get("state"))) != 1 {
			fail(w, http.StatusBadRequest, "This login did not start here, or took too long. Please try again.")
			return
		}
		if msg := r.URL.Query().Get("error"); msg != "" {
			fail(w, http.StatusUnauthorized, "The identity provider refused the login ("+msg+").")
			return
		}
		p, ok := provider()
		if !ok {
			fail(w, http.StatusServiceUnavailable, "The portal's identity provider is not configured.")
			return
		}
		disc, err := e.oidcDiscover(r, p)
		if err != nil {
			fail(w, http.StatusBadGateway, "The identity provider cannot be reached.")
			return
		}
		ctx := idpContext(r.Context(), p)
		cfg := oauthConfig(r, p, disc)
		token, err := cfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(tx.Verifier))
		if err != nil {
			fail(w, http.StatusBadGateway, "The identity provider did not complete the login.")
			return
		}
		id, err := verifiedIdentity(ctx, disc, p, token, tx.Nonce)
		if err != nil {
			markBlocked(w, blockSSO)
			fail(w, http.StatusUnauthorized, err.Error())
			return
		}
		maxAge := time.Duration(e.vpnIntSetting("wg_auth_max_age", 900)) * time.Second
		if id.authTime.IsZero() {
			fail(w, http.StatusUnauthorized, "The identity provider did not say when you authenticated (no auth_time claim), so this cannot count as a fresh login. Ask the administrator to enable it for this client.")
			return
		}
		if time.Since(id.authTime) > maxAge+authTimeSkew {
			fail(w, http.StatusUnauthorized, "The identity provider answered from an earlier login. Please log out there and log in again.")
			return
		}
		if token.RefreshToken == "" {
			fail(w, http.StatusUnauthorized, "The identity provider returned no refresh token, so quicgate could not keep checking that your account is still allowed. Ask the administrator to allow offline access for this client.")
			return
		}
		allowed := false
		for _, subj := range opts.Enrol {
			allowed = allowed || subjectMatchesOwner(subj, p.ID, id.sub, id.groups)
		}
		if !allowed {
			markBlocked(w, blockSSO)
			fail(w, http.StatusForbidden, id.email+" may not use the VPN.")
			return
		}
		now := time.Now()
		sess := e.newLease(now, store.VPNSession{Provider: p.ID, Sub: id.sub, Email: id.email, Groups: id.groups, RefreshToken: token.RefreshToken, LoginAt: now})
		sess.HardUntil = now.Add(time.Duration(e.vpnIntSetting("wg_session_days", 30)) * 24 * time.Hour)
		sess = capLease(sess)
		if err := e.store.LoginVPNSession(&sess); errors.Is(err, store.ErrOwnerBlocked) {
			markBlocked(w, blockSSO)
			fail(w, http.StatusForbidden, "An administrator has blocked this account from the VPN.")
			return
		} else if err != nil {
			log.Printf("vpn portal: login of %s: %v", id.email, err)
			fail(w, http.StatusInternalServerError, "The login could not be stored.")
			return
		}
		// A new session id at every login; the old one, if any, is dropped.
		if old, err := r.Cookie(portalCookie); err == nil {
			e.portal.drop(old.Value)
		}
		sid := e.portal.create(portalSession{provider: p.ID, sub: id.sub, email: id.email, expires: now.Add(portalIdle), authTime: id.authTime})
		setCookie(w, r, portalCookie, sid, 0, http.SameSiteStrictMode)
		e.refreshVPN(r.Context()) // the owner's devices are back
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// The API. Every call needs the session; every call that changes something
	// also needs an Origin that is exactly this portal, and JSON (S51).
	api := func(change bool, next func(w http.ResponseWriter, r *http.Request, s portalSession)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			ck, err := r.Cookie(portalCookie)
			if err != nil {
				writePortalErr(w, http.StatusUnauthorized, "not logged in")
				return
			}
			s, ok := e.portal.get(ck.Value)
			if !ok || s.provider != opts.ProviderID {
				writePortalErr(w, http.StatusUnauthorized, "not logged in")
				return
			}
			if change {
				if r.Header.Get("Origin") != requestOrigin(r) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
					writePortalErr(w, http.StatusForbidden, "this request did not come from the portal")
					return
				}
			}
			next(w, r, s)
		}
	}

	mux.HandleFunc("GET /.qg/vpn/api/me", api(false, func(w http.ResponseWriter, r *http.Request, s portalSession) {
		writePortalJSON(w, http.StatusOK, e.portalView(s))
	}))
	mux.HandleFunc("POST /.qg/vpn/api/devices", api(true, func(w http.ResponseWriter, r *http.Request, s portalSession) {
		var in struct{ Name, PublicKey string }
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			writePortalErr(w, http.StatusBadRequest, "invalid request")
			return
		}
		lease, err := e.store.GetVPNSession(s.provider, s.sub)
		if err != nil || !lease.Live(time.Now()) {
			writePortalErr(w, http.StatusForbidden, "your authorization has run out: log in again first")
			return
		}
		// A new device is a new credential. It takes a login that is fresh now,
		// not one that was fresh when this page was opened: a page kept open,
		// or a cookie that was copied, must not be enough (QG-08).
		if maxAge := time.Duration(e.vpnIntSetting("wg_auth_max_age", 900)) * time.Second; time.Since(s.authTime) > maxAge+authTimeSkew {
			writePortalErr(w, http.StatusUnauthorized, "adding a device takes a fresh login: log in again, then add the device")
			return
		}
		in.PublicKey = strings.TrimSpace(in.PublicKey)
		if err := wg.ValidKey(in.PublicKey); err != nil {
			writePortalErr(w, http.StatusBadRequest, "public key: "+err.Error())
			return
		}
		st := e.wgState.Load()
		if st == nil || !st.enabled || st.publicKey == "" {
			writePortalErr(w, http.StatusServiceUnavailable, "the VPN is switched off")
			return
		}
		if in.PublicKey == st.publicKey {
			writePortalErr(w, http.StatusBadRequest, "that is the server's own public key")
			return
		}
		psk, err := wg.NewPresharedKey()
		if err != nil {
			writePortalErr(w, http.StatusInternalServerError, "cannot make a key")
			return
		}
		d := store.WGDevice{Name: in.Name, Kind: "sso", PublicKey: in.PublicKey, Enabled: true, Provider: s.provider, Sub: s.sub, Email: s.email}
		if err := e.store.CreateWGDevice(&d, st.network, psk, e.vpnIntSetting("wg_devices_per_user", 5)); err != nil {
			writePortalErr(w, http.StatusBadRequest, err.Error())
			return
		}
		e.refreshVPN(r.Context())
		d.PresharedKey = psk // this once
		writePortalJSON(w, http.StatusCreated, d)
	}))
	mux.HandleFunc("DELETE /.qg/vpn/api/devices/{id}", api(true, func(w http.ResponseWriter, r *http.Request, s portalSession) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writePortalErr(w, http.StatusBadRequest, "invalid id")
			return
		}
		// Only the caller's own devices: the owner is part of the statement.
		owner := store.VPNSubject{Provider: s.provider, Sub: s.sub}
		if err := e.store.RevokeWGDevice(id, &owner); err != nil {
			writePortalErr(w, http.StatusNotFound, "no such device")
			return
		}
		e.refreshVPN(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /.qg/vpn/api/logout", api(true, func(w http.ResponseWriter, r *http.Request, s portalSession) {
		if ck, err := r.Cookie(portalCookie); err == nil {
			e.portal.drop(ck.Value)
		}
		setCookie(w, r, portalCookie, "", -1, http.SameSiteStrictMode)
		w.WriteHeader(http.StatusNoContent)
	}))
	// Disconnect: ends the lease, so every device of the caller leaves the
	// endpoint until the next login.
	mux.HandleFunc("POST /.qg/vpn/api/disconnect", api(true, func(w http.ResponseWriter, r *http.Request, s portalSession) {
		if lease, err := e.store.GetVPNSession(s.provider, s.sub); err == nil {
			_ = e.store.EndVPNSession(lease.ID, "ended", 0)
		}
		e.refreshVPN(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The portal hands out credentials: a session, and a device's
		// configuration with its preshared key. Over plain HTTP anybody on the
		// path reads both and can change the page that makes the private key,
		// so there is no portal over plain HTTP (QG-05). A development instance
		// without TLS altogether is the one exception.
		if !portalEncrypted(r) && !e.cfg.DisableTLS {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusPermanentRedirect)
				return
			}
			http.Error(w, "the VPN portal is only served over HTTPS", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	})
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func writePortalJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writePortalErr(w http.ResponseWriter, status int, msg string) {
	writePortalJSON(w, status, map[string]string{"error": msg})
}

// identity is what a verified ID token, or UserInfo, says about a person.
type identity struct {
	sub, email string
	groups     []string
	authTime   time.Time
}

func claimsIdentity(claims map[string]any, groupsClaim string) identity {
	var id identity
	id.sub, _ = claims["sub"].(string)
	id.email, _ = claims["email"].(string)
	if id.email == "" {
		id.email, _ = claims["preferred_username"].(string)
	}
	id.email = strings.ToLower(id.email)
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	if raw, ok := claims[groupsClaim].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok {
				id.groups = append(id.groups, s)
			}
		}
	}
	if at, ok := claims["auth_time"].(float64); ok && at > 0 {
		id.authTime = time.Unix(int64(at), 0)
	}
	return id
}

// verifiedIdentity checks the ID token of a token response (signature, issuer,
// audience, expiry, and the nonce when one is expected) and reads the person.
func verifiedIdentity(ctx context.Context, disc *oidc.Provider, p store.OIDCProvider, token *oauth2.Token, nonce string) (identity, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return identity{}, errors.New("the identity provider returned no ID token")
	}
	idToken, err := disc.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, raw)
	if err != nil {
		return identity{}, errors.New("the ID token did not verify")
	}
	if nonce != "" && idToken.Nonce != nonce {
		return identity{}, errors.New("the ID token belongs to another login")
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return identity{}, errors.New("the ID token cannot be read")
	}
	id := claimsIdentity(claims, p.GroupsClaim)
	if id.sub == "" {
		return identity{}, errors.New("the ID token names nobody")
	}
	if v, present := claims["email_verified"]; present && !claimIsTrue(v) {
		return identity{}, errors.New("the identity provider reports this address as unverified")
	}
	return id, nil
}

// newLease writes the lease and grace deadlines from a successful login or
// renewal at now. Nothing else ever writes them (S45).
func (e *Engine) newLease(now time.Time, s store.VPNSession) store.VPNSession {
	lease := time.Duration(e.vpnIntSetting("wg_lease_minutes", 10)) * time.Minute
	if lease < 2*time.Minute {
		lease = 2 * time.Minute
	}
	grace := time.Duration(e.vpnIntSetting("wg_outage_grace_minutes", 0)) * time.Minute
	if grace > time.Hour {
		grace = time.Hour
	}
	s.RenewedAt, s.LeaseUntil = now, now.Add(lease)
	s.GraceUntil = s.LeaseUntil.Add(grace)
	return s
}

// capLease keeps the lease and the grace within the hard limit.
func capLease(s store.VPNSession) store.VPNSession {
	if s.LeaseUntil.After(s.HardUntil) {
		s.LeaseUntil = s.HardUntil
	}
	if s.GraceUntil.After(s.HardUntil) {
		s.GraceUntil = s.HardUntil
	}
	return s
}

// portalView is what the portal page shows its owner.
func (e *Engine) portalView(s portalSession) map[string]any {
	out := map[string]any{"email": s.email, "devices": []store.WGDevice{}, "limit": e.vpnIntSetting("wg_devices_per_user", 5)}
	if lease, err := e.store.GetVPNSession(s.provider, s.sub); err == nil {
		out["lease"] = map[string]any{"live": lease.Live(time.Now()), "state": lease.State, "accessUntil": lease.AccessUntil(), "hardUntil": lease.HardUntil}
		var routes []store.VPNRoute
		if e.store.GetSetting("wg_lan_access", "") == "1" {
			if policies, err := e.store.ListVPNPolicies(); err == nil {
				for _, p := range policies {
					if subjectMatchesOwner(p.Subject, lease.Provider, lease.Sub, lease.Groups) {
						routes = append(routes, p.Routes...)
					}
				}
			}
		}
		out["routes"] = routes
	}
	status := map[int64]wg.PeerStatus{}
	for _, st := range e.wg.DeviceStatus() {
		status[st.ID] = st
	}
	if all, err := e.store.ListWGDevices(); err == nil {
		mine := []map[string]any{}
		for _, d := range all {
			if d.Kind != "sso" || d.Provider != s.provider || d.Sub != s.sub || d.RevokedAt != "" {
				continue
			}
			row := map[string]any{"id": d.ID, "name": d.Name, "address": d.Address, "createdAt": d.CreatedAt, "publicKey": d.PublicKey}
			if st, ok := status[d.ID]; ok {
				// Where and when a device was last seen makes a stolen one visible.
				row["connected"], row["lastHandshake"], row["lastEndpoint"] = true, st.LastHandshake, st.Endpoint
			}
			mine = append(mine, row)
		}
		out["devices"] = mine
	}
	if st := e.wgState.Load(); st != nil && st.enabled {
		out["server"] = map[string]any{"publicKey": st.publicKey, "endpoint": st.endpoint, "address": wg.TunnelAddress(st.network).String(), "network": st.network.String()}
	}
	return out
}

// refreshVPN applies the devices and leases of the moment to the endpoint,
// without rebuilding the routes: a login, an enrolment and every renewal need
// it, and a full reload is far more than they need.
func (e *Engine) refreshVPN(ctx context.Context) {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()
	e.syncWireGuard(ctx)
}

// ---- lease renewal (S44, S45) ----

const leaseTick = 30 * time.Second

// renewLeases renews the owners' leases when half of each has passed, and
// takes expired owners' devices off the endpoint. Admission checks the
// deadlines by itself (S2); this loop only tidies up and renews.
func (e *Engine) renewLeases() {
	for {
		time.Sleep(leaseTick)
		e.leaseTick(context.Background(), time.Now())
	}
}

func (e *Engine) leaseTick(ctx context.Context, now time.Time) {
	if st := e.wgState.Load(); st == nil || !st.enabled {
		return
	}
	sessions, err := e.store.ListVPNSessions()
	if err != nil {
		return
	}
	var live []string
	for _, s := range sessions {
		if s.State != "active" {
			continue
		}
		if !s.Live(now) {
			// The deadline passed without a renewal: lapsed, until a login.
			_ = e.store.EndVPNSession(s.ID, "lapsed", s.Generation)
			continue
		}
		live = append(live, ownerKey(s.Provider, s.Sub)+"@"+strconv.FormatInt(s.Generation, 10))
		half := s.RenewedAt.Add(s.LeaseUntil.Sub(s.RenewedAt) / 2)
		if now.After(half) {
			if _, busy := e.portal.renewing.LoadOrStore(s.ID, struct{}{}); !busy {
				go func(s store.VPNSession) {
					defer e.portal.renewing.Delete(s.ID)
					e.renewLease(ctx, s)
				}(s)
			}
		}
	}
	sort.Strings(live)
	now2 := strings.Join(live, ",")
	e.portal.mu.Lock()
	changed := now2 != e.portal.lastLive
	e.portal.lastLive = now2
	e.portal.mu.Unlock()
	if changed {
		e.refreshVPN(ctx)
	}
}

// definitive reports whether a refresh error says the grant is gone for good
// (the account was disabled, the session revoked), as opposed to the provider
// being unreachable or unwell.
func definitive(err error) bool {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		if re.ErrorCode == "invalid_grant" || re.ErrorCode == "invalid_client" || re.ErrorCode == "unauthorized_client" {
			return true
		}
		if re.Response != nil && (re.Response.StatusCode == http.StatusBadRequest || re.Response.StatusCode == http.StatusUnauthorized || re.Response.StatusCode == http.StatusForbidden) {
			return true
		}
	}
	return false
}

// renewLease redeems the refresh token and, on positive evidence, extends the
// lease. The result is committed only if the session is still the one this
// renewal started from (S44): an admin who ended it meanwhile wins.
func (e *Engine) renewLease(ctx context.Context, s store.VPNSession) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	from := s.Generation
	lapse := func(why string) {
		log.Printf("vpn: the authorization of %s ended: %s", s.Email, why)
		_ = e.store.EndVPNSession(s.ID, "lapsed", from)
		e.refreshVPN(ctx)
	}
	transient := func(why string) {
		log.Printf("vpn: renewing the authorization of %s failed, will retry: %s", s.Email, why)
		_ = e.store.MarkVPNSessionTransient(s.ID, from)
	}
	if s.RefreshToken == "" {
		lapse("no refresh token is stored (is the secret store locked?)")
		return
	}
	var p store.OIDCProvider
	found := false
	if all, err := e.store.ListOIDCProviders(); err == nil {
		for _, c := range all {
			if c.ID == s.Provider {
				p, found = c, true
			}
		}
	}
	if !found {
		lapse("its identity provider no longer exists")
		return
	}
	claimsSource := "id_token"
	for _, h := range e.portalHosts() {
		if h.Options.Portal.ProviderID == p.ID {
			claimsSource = h.Options.Portal.ClaimsSource
		}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	disc, err := e.oidcDiscover(req, p)
	if err != nil {
		transient("the identity provider cannot be reached")
		return
	}
	idpCtx := idpContext(ctx, p)
	cfg := oauth2.Config{ClientID: p.ClientID, ClientSecret: p.ClientSecret, Endpoint: disc.Endpoint()}
	token, err := cfg.TokenSource(idpCtx, &oauth2.Token{RefreshToken: s.RefreshToken}).Token()
	if err != nil {
		if definitive(err) {
			lapse("the identity provider refused to renew it")
		} else {
			transient(err.Error())
		}
		return
	}
	var id identity
	switch claimsSource {
	case "userinfo":
		ui, err := disc.UserInfo(idpCtx, oauth2.StaticTokenSource(token))
		if err != nil {
			transient("UserInfo: " + err.Error())
			return
		}
		var claims map[string]any
		if err := ui.Claims(&claims); err != nil {
			transient("UserInfo cannot be read")
			return
		}
		id = claimsIdentity(claims, p.GroupsClaim)
		id.sub = ui.Subject
	default:
		// OIDC makes the ID token optional in a refresh response. This profile
		// requires it: without it there is no fresh evidence about the groups.
		if id, err = verifiedIdentity(idpCtx, disc, p, token, ""); err != nil {
			lapse("the refresh gave no usable ID token (" + err.Error() + "); use the userinfo claims source for this provider")
			return
		}
	}
	if id.sub != s.Sub {
		lapse("the identity provider answered for another person")
		return
	}
	next := e.newLease(time.Now(), s)
	next.HardUntil = s.HardUntil
	next = capLease(next)
	next.Groups = id.groups
	if id.email != "" {
		next.Email = id.email
	}
	if token.RefreshToken != "" {
		next.RefreshToken = token.RefreshToken // the provider rotated it
	}
	if err := e.store.RenewVPNSession(&next, from); err != nil {
		if !errors.Is(err, store.ErrStaleSession) {
			log.Printf("vpn: storing the renewed authorization of %s: %v", s.Email, err)
		}
		return // stale: someone ended or replaced the session meanwhile, and they win
	}
	e.refreshVPN(ctx)
}

func (e *Engine) portalHosts() []store.Host {
	var out []store.Host
	if hosts, err := e.store.ListHosts(); err == nil {
		for _, h := range hosts {
			if h.Enabled && h.Type == "vpn-portal" && h.Options.Portal != nil {
				out = append(out, h)
			}
		}
	}
	return out
}
