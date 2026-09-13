//go:build !windows

package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Q16: `docker stop` sends SIGTERM. The process must shut down through the
// same path as Ctrl-C (listeners closed, UPnP released, access log flushed)
// and exit cleanly, not be killed by the default signal handling.
func TestSIGTERMShutsDownGracefully(t *testing.T) {
	if os.Getenv("QG_HELPER_MAIN") == "1" {
		main()
		return
	}
	var out lockedBuffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestSIGTERMShutsDownGracefully$")
	cmd.Env = append(os.Environ(), "QG_HELPER_MAIN=1", "QG_DATA="+t.TempDir(),
		"QG_TLS=off", "QG_HTTP=127.0.0.1:0", "QG_ADMIN=127.0.0.1:0")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(out.String(), "engine: http listening") {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("quicgate did not start:\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("process did not exit cleanly on SIGTERM: %v\n%s", err, out.String())
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("process still running 20s after SIGTERM:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "engine: shutdown complete") {
		t.Fatalf("SIGTERM did not go through the graceful shutdown path:\n%s", out.String())
	}
}
