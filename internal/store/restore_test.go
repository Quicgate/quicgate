package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// snapshotOf writes a snapshot of st and lets mutate change it the way an older
// version's database would differ.
func snapshotOf(t *testing.T, st *Store, mutate func(db *sql.DB)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snap.db")
	if err := st.Snapshot(path); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	mutate(db)
	_ = db.Close()
	return path
}

// Q10: a snapshot from a version that predates a table must not leave the live
// rows of that table in place (live API tokens surviving a restore).
func TestRestoreFromOlderSnapshotEmptiesTablesItLacks(t *testing.T) {
	st := openTestStore(t)
	snap := snapshotOf(t, st, func(db *sql.DB) {
		if _, err := db.Exec("DROP TABLE api_tokens"); err != nil {
			t.Fatal(err)
		}
	})
	live, err := st.CreateAPIToken("live")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RestoreFrom(snap); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if st.ValidAPIToken(live.Token) {
		t.Fatal("a live API token survived restoring a snapshot that has no token table")
	}
}

// Q10: columns are matched by name, so an older snapshot without a newer
// column restores, with the column's default.
func TestRestoreFromMatchesColumnsByName(t *testing.T) {
	st := openTestStore(t)
	h := &Host{Type: "proxy", Domains: []string{"old.test"}, CertMode: "none", Enabled: true,
		Upstream: Upstream{Scheme: "http", Host: "127.0.0.1", Port: 8080}}
	if err := st.CreateHost(h); err != nil {
		t.Fatal(err)
	}
	snap := snapshotOf(t, st, func(db *sql.DB) {
		if _, err := db.Exec("ALTER TABLE hosts DROP COLUMN locations"); err != nil {
			t.Fatal(err)
		}
	})
	if err := st.DeleteHost(h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RestoreFrom(snap); err != nil {
		t.Fatalf("restore of a snapshot missing a column: %v", err)
	}
	hosts, err := st.ListHosts()
	if err != nil || len(hosts) != 1 || hosts[0].Domains[0] != "old.test" {
		t.Fatalf("hosts after restore = %v (err %v), want old.test back", hosts, err)
	}
}

// Q10: a corrupt snapshot is refused and nothing changes.
func TestRestoreFromRejectsCorruptSnapshot(t *testing.T) {
	st := openTestStore(t)
	if err := st.CreateHost(&Host{Type: "proxy", Domains: []string{"keep.test"}, CertMode: "none", Enabled: true,
		Upstream: Upstream{Scheme: "http", Host: "127.0.0.1", Port: 8080}}); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.db")
	if err := writeFile(bad, []byte("this is not a database")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RestoreFrom(bad); err == nil {
		t.Fatal("a corrupt snapshot was restored")
	}
	if hosts, _ := st.ListHosts(); len(hosts) != 1 {
		t.Fatalf("a failed restore changed the configuration: %d hosts", len(hosts))
	}
}

func writeFile(path string, data []byte) error { return os.WriteFile(path, data, 0o600) }
