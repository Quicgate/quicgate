package engine

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"quicgate/internal/store"
)

// upgradeBackend answers an Upgrade request with 101 and then echoes bytes,
// and streams a line a time on /stream until the client goes away.
func upgradeBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.WriteHeader(http.StatusOK)
			for i := 0; ; i++ {
				if _, err := fmt.Fprintf(w, "tick %d\n", i); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(50 * time.Millisecond):
				}
			}
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = buf.Flush()
		_, _ = io.Copy(conn, buf)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// upgrade opens an upgraded connection to host through the public handler.
func upgrade(t *testing.T, public *httptest.Server, host string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", public.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n", host)
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade to %s: %v %v", host, resp, err)
	}
	return c, br
}

func echoes(c net.Conn, br *bufio.Reader) bool {
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping\n")); err != nil {
		return false
	}
	line, err := br.ReadString('\n')
	return err == nil && line == "ping\n"
}

// Making a host VPN only takes it away from whoever is connected from outside
// right now, not only from whoever comes next (QG-03). A WebSocket or a stream
// that was open would otherwise go on for as long as the client liked. Other
// hosts are left alone, and so is a request that outlived earlier reloads.
func TestLeavingThePublicSideEndsOpenPublicConnections(t *testing.T) {
	e, st := newTestEngine(t)
	backend := upgradeBackend(t)
	u, _ := url.Parse(backend.URL)
	port, _ := strconv.Atoi(u.Port())
	mk := func(domain string) *store.Host {
		h := &store.Host{Type: "proxy", Domains: []string{domain}, CertMode: "none", Enabled: true,
			Upstream: store.Upstream{Scheme: "http", Host: u.Hostname(), Port: port}}
		if err := st.CreateHost(h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	private, other, doomed := mk("private.test"), mk("other.test"), mk("doomed.test")
	reload(t, e)
	public := httptest.NewServer(http.HandlerFunc(e.serveHTTPS))
	t.Cleanup(public.Close)

	ws, wsr := upgrade(t, public, "private.test")
	keep, keepr := upgrade(t, public, "other.test")
	gone, goner := upgrade(t, public, "doomed.test")

	req, _ := http.NewRequest(http.MethodGet, public.URL+"/stream", nil)
	req.Host = "private.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	stream := bufio.NewReader(resp.Body)
	if line, err := stream.ReadString('\n'); err != nil || !strings.HasPrefix(line, "tick") {
		t.Fatalf("the stream does not run: %q %v", line, err)
	}

	// Reloads that change nothing about these hosts end nothing, however many.
	for i := 0; i < 3; i++ {
		reload(t, e)
	}
	if !echoes(ws, wsr) || !echoes(keep, keepr) || !echoes(gone, goner) {
		t.Fatal("a reload that changed nothing ended an open connection")
	}

	private.Options.VPNOnly = true
	if err := st.UpdateHost(private); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteHost(doomed.ID); err != nil {
		t.Fatal(err)
	}
	reload(t, e)

	if echoes(ws, wsr) {
		t.Error("the upgraded public connection to a host that is now VPN only still carries data")
	}
	if echoes(gone, goner) {
		t.Error("the upgraded public connection to a deleted host still carries data")
	}
	ended := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.ReadString('\n'); err != nil {
				ended <- err
				return
			}
		}
	}()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Error("the public stream from a host that is now VPN only goes on")
	}
	if !echoes(keep, keepr) {
		t.Error("the connection to another host was ended too")
	}
	_ = other

	// And nobody new gets in from outside.
	req2, _ := http.NewRequest(http.MethodGet, public.URL+"/", nil)
	req2.Host = "private.test"
	if resp2, err := http.DefaultClient.Do(req2); err == nil {
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusNotFound {
			t.Errorf("a new public request to the VPN-only host: %d, want 404", resp2.StatusCode)
		}
	}
	e.publicReqs.mu.Lock()
	left := len(e.publicReqs.open)
	e.publicReqs.mu.Unlock()
	if left != 1 {
		t.Errorf("%d hosts still have public requests registered, want the one that stayed public", left)
	}
}
