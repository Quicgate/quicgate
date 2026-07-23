package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// accessLogger writes one JSON line per proxied request to a size-rotated
// file. Structured with the real client IP so ban tools (fail2ban, CrowdSec)
// can consume it directly. It also keeps counters for the metrics endpoint.
type accessLogger struct {
	out       *lumberjack.Logger
	enc       chan []byte
	total     atomic.Uint64
	bytes     atomic.Uint64
	status2xx atomic.Uint64
	status3xx atomic.Uint64
	status4xx atomic.Uint64
	status5xx atomic.Uint64
}

// promText renders the counters in Prometheus exposition format.
func (l *accessLogger) promText() string {
	return fmt.Sprintf(`# HELP quicgate_requests_total Total proxied requests.
# TYPE quicgate_requests_total counter
quicgate_requests_total %d
# HELP quicgate_responses_total Responses by status class.
# TYPE quicgate_responses_total counter
quicgate_responses_total{class="2xx"} %d
quicgate_responses_total{class="3xx"} %d
quicgate_responses_total{class="4xx"} %d
quicgate_responses_total{class="5xx"} %d
# HELP quicgate_response_bytes_total Total response bytes.
# TYPE quicgate_response_bytes_total counter
quicgate_response_bytes_total %d
`, l.total.Load(), l.status2xx.Load(), l.status3xx.Load(), l.status4xx.Load(), l.status5xx.Load(), l.bytes.Load())
}

// MetricsText exposes the Prometheus text for the admin /metrics endpoint.
func (e *Engine) MetricsText() string { return e.accessLog.promText() }

func newAccessLogger(dir string) *accessLogger {
	l := &accessLogger{
		out: &lumberjack.Logger{
			Filename:   dir + "/logs/access.log",
			MaxSize:    20, // MB
			MaxBackups: 5,
			Compress:   true,
		},
		enc: make(chan []byte, 1024),
	}
	go func() {
		for line := range l.enc {
			_, _ = l.out.Write(append(line, '\n'))
		}
	}()
	return l
}

type accessRecord struct {
	Time     string `json:"ts"`
	ClientIP string `json:"client_ip"`
	Host     string `json:"host"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Bytes    int64  `json:"bytes"`
	DurMS    int64  `json:"dur_ms"`
	Proto    string `json:"proto"`
	Scheme   string `json:"scheme"`
	UA       string `json:"ua,omitempty"`
}

// statusWriter captures status and byte count without altering behavior.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Flush keeps SSE/streaming working through the wrapper.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// wrap returns next wrapped with JSON access logging.
func (l *accessLogger) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next(sw, r)
		l.total.Add(1)
		l.bytes.Add(uint64(sw.bytes))
		switch sw.status / 100 {
		case 2:
			l.status2xx.Add(1)
		case 3:
			l.status3xx.Add(1)
		case 4:
			l.status4xx.Add(1)
		case 5:
			l.status5xx.Add(1)
		}
		ip := r.RemoteAddr
		if h, _, err := net.SplitHostPort(ip); err == nil {
			ip = h
		}
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		rec := accessRecord{
			Time:     start.UTC().Format(time.RFC3339Nano),
			ClientIP: ip,
			Host:     r.Host,
			Method:   r.Method,
			Path:     r.URL.Path,
			Status:   sw.status,
			Bytes:    sw.bytes,
			DurMS:    time.Since(start).Milliseconds(),
			Proto:    r.Proto,
			Scheme:   scheme,
			UA:       r.UserAgent(),
		}
		line, err := json.Marshal(rec)
		if err != nil {
			return
		}
		select {
		case l.enc <- line:
		default: // never block the request path on a slow disk
		}
	}
}
