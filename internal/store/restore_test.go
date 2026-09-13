package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// restoreTestStore opens a store with the admin account every real backup has.
func restoreTestStore(t *testing.T) *Store {
	t.Helper()
	st := openTestStore(t)
	if err := st.CreateUser("admin@example.com", "hash", false); err != nil {
		t.Fatal(err)
	}
	return st
}

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
	st := restoreTestStore(t)
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
	st := restoreTestStore(t)
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
	st := restoreTestStore(t)
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

// A valid SQLite file that is not a quicgate backup is refused. Restoring it
// used to empty every table (none of them are in it) and report success,
// wiping the configuration and the admin account.
func TestRestoreFromRejectsForeignDatabase(t *testing.T) {
	st := restoreTestStore(t)
	if err := st.CreateHost(refTestHost("keep.test")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "other.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE notes (body TEXT)"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	if _, err := st.RestoreFrom(path); err == nil {
		t.Fatal("a database that is not a quicgate backup was restored")
	}
	hosts, _ := st.ListHosts()
	users, _ := st.CountUsers()
	if len(hosts) != 1 || users != 1 {
		t.Fatalf("refused restore changed live state: %d hosts, %d users", len(hosts), users)
	}

	// Having an account table is not enough: without the hosts table it is
	// still not a quicgate backup.
	partial := filepath.Join(t.TempDir(), "partial.db")
	db, err = sql.Open("sqlite", partial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, hash TEXT); INSERT INTO users (email, hash) VALUES ('x@example.com', 'h')"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := st.RestoreFrom(partial); err == nil {
		t.Fatal("a database without a hosts table was restored")
	}
	if hosts, _ := st.ListHosts(); len(hosts) != 1 {
		t.Fatalf("refused restore changed live hosts: %d", len(hosts))
	}

	// Tables with the right names but none of the right columns share nothing
	// with the schema: restoring them would empty hosts and users.
	for name, setup := range map[string]string{
		"foreign hosts and users": "CREATE TABLE hosts (body TEXT); INSERT INTO hosts VALUES ('x'); " +
			"CREATE TABLE users (body TEXT); INSERT INTO users VALUES ('x')",
		"foreign hosts, real users": "CREATE TABLE hosts (body TEXT); INSERT INTO hosts VALUES ('x'); " +
			"CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, hash TEXT, must_change INTEGER NOT NULL DEFAULT 0); " +
			"INSERT INTO users (email, hash) VALUES ('other@example.com', 'hash')",
	} {
		path := filepath.Join(t.TempDir(), "crafted.db")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(setup); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
		if _, err := st.RestoreFrom(path); err == nil {
			t.Fatalf("%s: a database with foreign columns was restored", name)
		}
		hosts, _ := st.ListHosts()
		users, _ := st.CountUsers()
		if len(hosts) != 1 || users != 1 {
			t.Fatalf("%s: refused restore changed live state: %d hosts, %d users", name, len(hosts), users)
		}
	}
}

// The restored accounts must include one that can sign in: a users table whose
// rows carry no password hash leaves nobody able to administer the proxy.
func TestRestoreFromRejectsSnapshotWithoutUsableAdmin(t *testing.T) {
	st := restoreTestStore(t)
	snap := snapshotOf(t, st, func(db *sql.DB) {
		if _, err := db.Exec("UPDATE users SET hash = ''"); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := st.RestoreFrom(snap); err == nil {
		t.Fatal("a backup whose only account has no password hash was restored")
	}
	if users, _ := st.CountUsers(); users != 1 {
		t.Fatalf("refused restore changed live users: %d", users)
	}
}

// A backup without an admin account is refused: restoring it would lock the
// operator out, and the next start would recreate the default credentials.
func TestRestoreFromRejectsSnapshotWithoutAdmin(t *testing.T) {
	st := restoreTestStore(t)
	snap := snapshotOf(t, st, func(db *sql.DB) {
		if _, err := db.Exec("DELETE FROM users"); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := st.RestoreFrom(snap); err == nil {
		t.Fatal("a backup without any admin account was restored")
	}
	if users, _ := st.CountUsers(); users != 1 {
		t.Fatalf("refused restore changed live users: %d", users)
	}
}

// A backup whose rows cannot be decoded is refused inside the transaction.
// Committing it left an instance whose every reload failed.
func TestRestoreFromRejectsUnreadableRows(t *testing.T) {
	st := restoreTestStore(t)
	refTestACL(t, st, "lan")
	snap := snapshotOf(t, st, func(db *sql.DB) {
		if _, err := db.Exec(`UPDATE access_lists SET rules = '{"not":"a list"}'`); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := st.RestoreFrom(snap); err == nil {
		t.Fatal("a backup with unreadable access list rules was restored")
	}
	if lists, err := st.ListAccessLists(); err != nil || len(lists) != 1 {
		t.Fatalf("refused restore changed live access lists: %v %v", lists, err)
	}
}
