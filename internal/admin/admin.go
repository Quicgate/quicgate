package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"quicgate/internal/engine"
	"quicgate/internal/store"
)

const sessionTTL = 12 * time.Hour

type session struct {
	userID  int64
	email   string
	expires time.Time
}

// Server is the management API + embedded UI, served on its own port.
type Server struct {
	store    *store.Store
	engine   *engine.Engine
	webFS    fs.FS
	mu       sync.Mutex
	sessions map[string]session
}

func New(st *store.Store, eng *engine.Engine, webFS fs.FS) *Server {
	return &Server{store: st, engine: eng, webFS: webFS, sessions: map[string]session{}}
}

// EnsureAdmin seeds the NPM-style default admin on first run.
func (s *Server) EnsureAdmin() error {
	n, err := s.store.CountUsers()
	if err != nil || n > 0 {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.store.CreateUser("admin@example.com", string(hash), true); err != nil {
		return err
	}
	log.Printf("admin: created default user admin@example.com / changeme (password change is forced on first login)")
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.auth(s.handleLogout))
	mux.HandleFunc("GET /api/me", s.auth(s.handleMe))
	mux.HandleFunc("POST /api/password", s.auth(s.handlePassword))
	mux.HandleFunc("GET /api/hosts", s.auth(s.handleListHosts))
	mux.HandleFunc("POST /api/hosts", s.auth(s.handleCreateHost))
	mux.HandleFunc("PUT /api/hosts/{id}", s.auth(s.handleUpdateHost))
	mux.HandleFunc("DELETE /api/hosts/{id}", s.auth(s.handleDeleteHost))
	mux.HandleFunc("GET /api/certs", s.auth(s.handleCerts))
	mux.HandleFunc("GET /api/access-lists", s.auth(s.handleListAccessLists))
	mux.HandleFunc("POST /api/access-lists", s.auth(s.handleCreateAccessList))
	mux.HandleFunc("PUT /api/access-lists/{id}", s.auth(s.handleUpdateAccessList))
	mux.HandleFunc("DELETE /api/access-lists/{id}", s.auth(s.handleDeleteAccessList))
	mux.HandleFunc("GET /api/settings", s.auth(s.handleGetSettings))
	mux.HandleFunc("PUT /api/settings", s.auth(s.handlePutSettings))
	mux.HandleFunc("GET /api/streams", s.auth(s.handleListStreams))
	mux.HandleFunc("POST /api/streams", s.auth(s.handleCreateStream))
	mux.HandleFunc("PUT /api/streams/{id}", s.auth(s.handleUpdateStream))
	mux.HandleFunc("DELETE /api/streams/{id}", s.auth(s.handleDeleteStream))
	mux.Handle("/", http.FileServerFS(s.webFS))
	return mux
}

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

// settingsKeys is the closed set of UI-editable settings; unknown keys are
// rejected, in keeping with the no-silent-drop contract.
var settingsKeys = map[string]bool{
	"acme_staging": true, // "1" = Let's Encrypt staging CA
	"acme_email":   true,
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	all, err := s.store.AllSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]string{}
	for k := range settingsKeys {
		out[k] = all[k]
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := decodeStrict(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for k := range body {
		if !settingsKeys[k] {
			writeErr(w, http.StatusBadRequest, "unsupported setting: "+k)
			return
		}
	}
	for k, v := range body {
		if err := s.store.SetSetting(k, v); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.reload(r.Context())
	s.handleGetSettings(w, r)
}

func (s *Server) handleListAccessLists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.store.ListAccessLists()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if lists == nil {
		lists = []store.AccessList{}
	}
	writeJSON(w, http.StatusOK, lists)
}

func (s *Server) handleCreateAccessList(w http.ResponseWriter, r *http.Request) {
	var a store.AccessList
	if err := decodeStrict(r, &a); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateAccessList(&a); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) handleUpdateAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var a store.AccessList
	if err := decodeStrict(r, &a); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.ID = id
	if err := s.store.UpdateAccessList(&a); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "access list not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleDeleteAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteAccessList(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "access list not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListStreams(w http.ResponseWriter, r *http.Request) {
	streams, err := s.store.ListStreams()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if streams == nil {
		streams = []store.Stream{}
	}
	writeJSON(w, http.StatusOK, streams)
}

func (s *Server) handleCreateStream(w http.ResponseWriter, r *http.Request) {
	var st store.Stream
	if err := decodeStrict(r, &st); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateStream(&st, s.engine.ReservedPorts()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusCreated, st)
}

func (s *Server) handleUpdateStream(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var st store.Stream
	if err := decodeStrict(r, &st); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	st.ID = id
	if err := s.store.UpdateStream(&st, s.engine.ReservedPorts()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "stream not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleDeleteStream(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteStream(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "stream not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type ctxKey int

const sessionKey ctxKey = 0

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("qg_session")
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "not logged in")
			return
		}
		s.mu.Lock()
		sess, ok := s.sessions[c.Value]
		if ok && time.Now().After(sess.expires) {
			delete(s.sessions, c.Value)
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusUnauthorized, "session expired")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct{ Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	u, err := s.store.GetUserByEmail(body.Email)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(body.Password)) != nil {
		time.Sleep(400 * time.Millisecond) // flat cost for wrong email and wrong password alike
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		writeErr(w, http.StatusInternalServerError, "entropy failure")
		return
	}
	id := hex.EncodeToString(tok)
	s.mu.Lock()
	s.sessions[id] = session{userID: u.ID, email: u.Email, expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "qg_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"email": u.Email, "mustChange": u.MustChange})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("qg_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "qg_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessionKey).(session)
	u, err := s.store.GetUserByEmail(sess.email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"email": u.Email, "mustChange": u.MustChange})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	sess := r.Context().Value(sessionKey).(session)
	var body struct{ Current, New string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(body.New) < 8 {
		writeErr(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	u, err := s.store.GetUserByEmail(sess.email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(body.Current)) != nil {
		writeErr(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.New), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetPassword(u.ID, string(hash)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.ListHosts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hosts == nil {
		hosts = []store.Host{}
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	var h store.Host
	if err := decodeStrict(r, &h); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateHost(&h); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusCreated, h)
}

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var h store.Host
	if err := decodeStrict(r, &h); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.ID = id
	if err := s.store.UpdateHost(&h); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "host not found")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteHost(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "host not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.reload(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	statuses := s.engine.CertStatuses(r.Context())
	if statuses == nil {
		statuses = []engine.CertStatus{}
	}
	writeJSON(w, http.StatusOK, statuses)
}

func (s *Server) reload(ctx context.Context) {
	if err := s.engine.Reload(ctx); err != nil {
		log.Printf("admin: reload after change failed: %v", err)
	}
}

// decodeStrict rejects unknown fields so a typo'd or removed option can never
// be silently dropped, which is the whole contract of structured options.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return errors.New("unsupported option: " + err.Error())
		}
		return err
	}
	return nil
}
