package admin

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxRestoreBytes = 200 << 20

// maxRestoreExpandedBytes caps what an upload may expand to. The compressed
// limit above does not bound this: gzip happily turns a few megabytes of zeroes
// into hundreds of gigabytes, which would fill the data volume before any of
// the archive was validated.
const maxRestoreExpandedBytes = 2 << 30

// handleBackup sends a tar.gz of everything: a consistent SQLite snapshot plus
// the certificate storage tree. The archive is built in full before anything
// is sent, so a file that cannot be read fails the request with an error
// instead of producing a truncated archive behind a 200.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	archive, err := os.CreateTemp(s.dataDir, ".backup-*.tar.gz")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.Remove(archive.Name())
	defer archive.Close()

	if err := s.writeBackup(archive); err != nil {
		writeErr(w, http.StatusInternalServerError, "backup failed: "+err.Error())
		return
	}
	size, err := archive.Seek(0, io.SeekCurrent)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="quicgate-backup-%s.tar.gz"`, time.Now().Format("20060102-150405")))
	_, _ = io.Copy(w, archive)
}

// writeBackup writes the archive to out and reports the first failure.
func (s *Server) writeBackup(out io.Writer) error {
	snap := filepath.Join(s.dataDir, fmt.Sprintf(".backup-%d.db", time.Now().UnixNano()))
	if err := s.store.Snapshot(snap); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	defer os.Remove(snap)

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	if err := addFileToTar(tw, snap, "quicgate.db"); err != nil {
		return err
	}
	certRoot := filepath.Join(s.dataDir, "certs")
	if _, err := os.Stat(certRoot); err == nil {
		err := filepath.Walk(certRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(s.dataDir, path)
			if err != nil {
				return err
			}
			return addFileToTar(tw, path, filepath.ToSlash(rel))
		})
		if err != nil {
			return fmt.Errorf("certificates: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("certificates: %w", err)
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func addFileToTar(tw *tar.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: info.Size(), ModTime: info.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// handleRestore accepts a backup tar.gz and restores it as one unit: the
// archive is unpacked and checked first, the certificate tree is swapped in,
// the database is replaced in a transaction, and a failure at any step puts the
// previous certificates back and leaves the database untouched. It never
// reports success for a restore that did not fully apply. Afterwards every
// admin session is revoked (the restored users, passwords and tokens are now
// the ones that apply) and the engine reloads, which also picks up the
// restored SSO signing key.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	tmp, err := os.MkdirTemp(s.dataDir, ".restore-*")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.RemoveAll(tmp)

	gz, err := gzip.NewReader(http.MaxBytesReader(w, r.Body, maxRestoreBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "not a gzip archive: "+err.Error())
		return
	}
	tr := tar.NewReader(gz)
	sawDB, sawCerts := false, false
	seen := map[string]bool{}
	var expanded int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad archive: "+err.Error())
			return
		}
		name := filepath.ToSlash(hdr.Name)
		// Only the paths a backup produces; anything else (traversal,
		// absolute paths, unexpected files) is rejected outright.
		if name != "quicgate.db" && !strings.HasPrefix(name, "certs/") {
			writeErr(w, http.StatusBadRequest, "unexpected file in archive: "+name)
			return
		}
		if strings.Contains(name, "..") {
			writeErr(w, http.StatusBadRequest, "path traversal in archive")
			return
		}
		// Only real files: a symlink or device entry has no business in a
		// backup, and honouring one would be a way out of the temp directory.
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			writeErr(w, http.StatusBadRequest, "unsupported archive entry: "+name)
			return
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		// A file must be named inside certs/, never certs/ itself: written as a
		// file, that name would replace the certificate directory.
		if strings.HasSuffix(name, "/") {
			writeErr(w, http.StatusBadRequest, "unsupported archive entry: "+name)
			return
		}
		if seen[name] {
			writeErr(w, http.StatusBadRequest, "duplicate entry in archive: "+name)
			return
		}
		seen[name] = true
		if name == "quicgate.db" {
			sawDB = true
		} else {
			sawCerts = true
		}
		dst := filepath.Join(tmp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		room := maxRestoreExpandedBytes - expanded
		n, err := io.Copy(f, io.LimitReader(tr, room+1))
		expanded += n
		if err == nil && n > room {
			f.Close()
			writeErr(w, http.StatusBadRequest, "archive expands beyond the restore size limit")
			return
		}
		if err != nil {
			f.Close()
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := f.Close(); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if !sawDB {
		writeErr(w, http.StatusBadRequest, "archive contains no quicgate.db")
		return
	}

	// Swap the certificate tree first, keeping the current one to put back.
	// An archive without certificates keeps the current tree: replacing it
	// with nothing would force every certificate to be issued again.
	live := filepath.Join(s.dataDir, "certs")
	var rollback, commit func() error
	if sawCerts {
		staged := filepath.Join(tmp, "certs")
		if info, err := os.Lstat(staged); err != nil || !info.IsDir() {
			writeErr(w, http.StatusBadRequest, "restore failed, nothing was changed: the archive's certificates are not a directory")
			return
		}
		rollback, commit, err = swapDir(live, staged)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "restore failed, nothing was changed: certificates: "+err.Error())
			return
		}
	}
	warnings, err := s.store.RestoreFrom(filepath.Join(tmp, "quicgate.db"))
	if err != nil {
		msg := "restore failed, nothing was changed: " + err.Error()
		if rollback != nil {
			if rbErr := rollback(); rbErr != nil {
				msg = "restore failed and the previous certificates could not be put back (" + rbErr.Error() + "): " + err.Error()
			}
		}
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if commit != nil {
		_ = commit() // only a leftover copy of the old certificates if this fails
	}
	s.revokeSessions(func(session) bool { return true }, "")

	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "restored, but applying it failed: "+err.Error())
		return
	}
	certs := "replaced"
	if !sawCerts {
		certs = "kept (the archive contains none)"
	}
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "restored", "certificates": certs, "warnings": warnings, "reauthenticate": true,
	})
}

// swapDir moves staged into place at live, keeping the previous live tree
// aside until the caller knows whether the restore succeeded: rollback puts the
// previous tree back, commit deletes it. staged must be on the same filesystem
// as live (it is: restores unpack beneath the data directory).
func swapDir(live, staged string) (rollback, commit func() error, err error) {
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	old := live + ".previous-" + hex.EncodeToString(suffix)
	hadLive := false
	if info, err := os.Lstat(live); err == nil {
		if !info.IsDir() {
			return nil, nil, fmt.Errorf("%s exists and is not a directory", live)
		}
		if err := os.Rename(live, old); err != nil {
			return nil, nil, err
		}
		hadLive = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if err := os.Rename(staged, live); err != nil {
		if hadLive {
			_ = os.Rename(old, live)
		}
		return nil, nil, err
	}
	rollback = func() error {
		if err := os.RemoveAll(live); err != nil {
			return err
		}
		if hadLive {
			return os.Rename(old, live)
		}
		return nil
	}
	commit = func() error {
		if hadLive {
			return os.RemoveAll(old)
		}
		return nil
	}
	return rollback, commit, nil
}
