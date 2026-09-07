package files

import (
	"os"
	"path/filepath"
)

// AtomicWrite ensures a file is fully written before becoming visible to
// Caddy. It writes to a unique temp file (CreateTemp) and then performs an
// atomic rename. The temp file is removed if the write or the rename fails
// (no stale .tmp ever remains).
func AtomicWrite(path string, content []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	// If anything fails before the rename, remove the temp file.
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	// 0644 permissions (world-readable) by design (amendment A, R4-006): the
	// overlays contain no secrets and Caddy runs as UID 1337, which must be
	// able to read them. CreateTemp creates with 0600, so it is explicitly
	// adjusted before the rename.
	if err = tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}

	// os.Rename is atomic on Linux when it is the same filesystem.
	return os.Rename(tmpPath, path)
}
