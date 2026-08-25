package files

import (
	"os"
	"path/filepath"
)

// AtomicWrite asegura que un archivo se escriba por completo antes de ser visible para Caddy.
// Escribe en un archivo temporal único (CreateTemp) y luego ejecuta un renombre atómico.
// El temporal se elimina si la escritura o el rename fallan (nunca queda .tmp stale).
func AtomicWrite(path string, content []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	// Si algo falla antes del rename, eliminar el temporal.
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	// Permisos 0644 (world-readable) por diseño (enmienda A, R4-006): los overlays
	// no contienen secretos y Caddy corre como UID 1337, que debe poder leerlos.
	// CreateTemp crea con 0600, por eso se ajusta explícitamente antes del rename.
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

	// os.Rename es atómico en Linux si es el mismo sistema de archivos.
	return os.Rename(tmpPath, path)
}
