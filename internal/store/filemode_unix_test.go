//go:build unix

package store

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The database holds the password hashes, the sealed secrets and the whole
// configuration. SQLite creates it with the process umask (0644 as a rule) and
// nothing tightened it; Open now makes the file, its write-ahead log and its
// shared memory owner-only, whatever the umask.
func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	noKeyEnv(t)
	path := filepath.Join(t.TempDir(), "quicgate.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetSetting("acme_email", "ops@example.com"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatalf("%s: %v (expected next to the database while it is open)", f, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %04o, want 0600", filepath.Base(f), fi.Mode().Perm())
		}
	}
}
