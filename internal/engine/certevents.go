package engine

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// certEvent is the last known ACME outcome for one domain, shown in the UI
// so renewal failures are visible instead of silent.
type certEvent struct {
	OK    bool
	Error string
	At    time.Time
}

type certTracker struct {
	mu           sync.Mutex
	events       map[string]certEvent
	lastNotified map[string]time.Time
	notifyURL    func() string // read at send time so setting changes apply live
}

func newCertTracker(notifyURL func() string) *certTracker {
	return &certTracker{events: map[string]certEvent{}, lastNotified: map[string]time.Time{}, notifyURL: notifyURL}
}

// handle consumes certmagic's OnEvent stream.
func (t *certTracker) handle(_ context.Context, event string, data map[string]any) error {
	name, _ := data["identifier"].(string)
	if name == "" {
		name, _ = data["name"].(string)
	}
	if name == "" {
		return nil
	}
	switch event {
	case "cert_obtained":
		t.mu.Lock()
		t.events[name] = certEvent{OK: true, At: time.Now()}
		t.mu.Unlock()
	case "cert_failed":
		msg := "unknown error"
		if e, ok := data["error"].(error); ok {
			msg = e.Error()
		} else if s, ok := data["error"].(string); ok {
			msg = s
		}
		t.mu.Lock()
		t.events[name] = certEvent{OK: false, Error: msg, At: time.Now()}
		notify := time.Since(t.lastNotified[name]) > time.Hour
		if notify {
			t.lastNotified[name] = time.Now()
		}
		t.mu.Unlock()
		log.Printf("cert: FAILED for %s: %s", name, msg)
		if notify {
			go t.send(fmt.Sprintf("quicgate: certificate for %s failed to issue/renew: %s", name, firstLine(msg)))
		}
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

// send POSTs a plain-text message to the configured webhook (ntfy/Gotify
// style: text body, Title header). No URL configured = silently skipped.
func (t *certTracker) send(msg string) {
	url := t.notifyURL()
	if url == "" {
		return
	}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(msg))
	if err != nil {
		return
	}
	req.Header.Set("Title", "quicgate alert")
	req.Header.Set("Content-Type", "text/plain")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("notify: %v", err)
		return
	}
	resp.Body.Close()
	log.Printf("notify: sent (%d)", resp.StatusCode)
}

// get returns the tracked event for a domain, if any.
func (t *certTracker) get(domain string) (certEvent, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ev, ok := t.events[domain]
	return ev, ok
}

// SendTest fires a test notification regardless of debounce.
func (t *certTracker) SendTest() {
	t.send("quicgate: test notification, the webhook works")
}
