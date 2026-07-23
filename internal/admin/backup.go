package admin

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxRestoreBytes = 200 << 20

// handleBackup streams a tar.gz of everything: a consistent SQLite snapshot
// plus the certmagic storage tree.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	snap := filepath.Join(s.dataDir, fmt.Sprintf(".backup-%d.db", time.Now().UnixNano()))
	if err := s.store.Snapshot(snap); err != nil {
		writeErr(w, http.StatusInternalServerError, "snapshot: "+err.Error())
		return
	}
	defer os.Remove(snap)

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="quicgate-backup-%s.tar.gz"`, time.Now().Format("20060102-150405")))
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	if err := addFileToTar(tw, snap, "quicgate.db"); err != nil {
		return // headers already sent; client sees a truncated archive
	}
	certRoot := filepath.Join(s.dataDir, "certs")
	_ = filepath.Walk(certRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.dataDir, path)
		if err != nil {
			return nil
		}
		return addFileToTar(tw, path, filepath.ToSlash(rel))
	})
	_ = tw.Close()
	_ = gz.Close()
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

// handleRestore accepts a backup tar.gz, restores the database atomically,
// unpacks the cert tree, and reloads the engine.
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
	sawDB := false
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
		if name == "quicgate.db" {
			sawDB = true
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
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		f.Close()
	}
	if !sawDB {
		writeErr(w, http.StatusBadRequest, "archive contains no quicgate.db")
		return
	}

	if err := s.store.RestoreFrom(filepath.Join(tmp, "quicgate.db")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Cert files second: even if a copy fails the config db is consistent
	// and certmagic will simply re-issue whatever is missing.
	restoredCerts := filepath.Join(tmp, "certs")
	_ = filepath.Walk(restoredCerts, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(tmp, path)
		dst := filepath.Join(s.dataDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		_ = os.WriteFile(dst, data, 0o600)
		return nil
	})

	if err := s.reload(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "change saved, but applying it failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "restored"})
}
