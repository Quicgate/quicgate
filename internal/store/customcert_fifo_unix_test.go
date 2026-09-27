//go:build unix

package store

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO given as a certificate path used to block the import for good (the
// open waits for a writer that never comes) and with it the admin request. The
// import refuses anything but a regular file before opening it.
func TestImportCertFromFileDoesNotBlockOnAFIFO(t *testing.T) {
	st := openTestStore(t)
	dir := t.TempDir()
	_, key := certFiles(t, dir)
	fifo := filepath.Join(dir, "cert.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := st.ImportCertFromFile("fifo", fifo, key)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Fatalf("a FIFO: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO as a certificate file blocked: the import must refuse anything but a regular file")
	}
}
