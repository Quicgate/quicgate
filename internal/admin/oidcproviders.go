package admin

import (
	"database/sql"
	"errors"
	"net/http"

	"quicgate/internal/store"
)

// CRUD for the OIDC providers that proxy hosts reference for built-in SSO.
// The client secret is write-mostly: list responses mask it, and an empty
// secret on update keeps the stored one, so the UI never round-trips it.

func maskProvider(p store.OIDCProvider) store.OIDCProvider {
	if p.ClientSecret != "" {
		p.ClientSecret = "********"
	}
	return p
}

func (s *Server) handleListOIDCProviders(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListOIDCProviders()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]store.OIDCProvider, 0, len(list))
	for _, p := range list {
		out = append(out, maskProvider(p))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	var p store.OIDCProvider
	if err := decodeStrict(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateOIDCProvider(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, maskProvider(p))
}

func (s *Server) handleUpdateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var p store.OIDCProvider
	if err := decodeStrict(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p.ID = id
	// The UI echoes the mask back when the secret was left untouched.
	if p.ClientSecret == "********" {
		p.ClientSecret = ""
	}
	if err := s.store.UpdateOIDCProvider(&p); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "provider not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, maskProvider(p))
}

func (s *Server) handleDeleteOIDCProvider(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	// The store refuses while a host, a path rule or the admin login still uses
	// the provider.
	if err := s.store.DeleteOIDCProvider(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "provider not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
