package engine

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// accessLogger writes one JSON line per proxied request to a size-rotated
// file. Structured with the real client IP so ban tools (fail2ban, CrowdSec)
// can consume it directly.
type accessLogger struct {
	out *lumberjack.Logger
	enc chan []byte
}

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
