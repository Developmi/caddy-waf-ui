package files_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/files"
)

func TestAtomicWrite(t *testing.T) {
	// Crear un directorio temporal para la prueba
	tmpDir, err := os.MkdirTemp("", "caddy-waf-test-*")
	if err != nil {
		t.Fatalf("Fallo al crear directorio temporal: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }() // Limpieza al finalizar

	targetPath := filepath.Join(tmpDir, "test-config.conf")
	content := []byte("SecRuleEngine On")

	// Ejecutar la escritura atómica
	err = files.AtomicWrite(targetPath, content)
	if err != nil {
		t.Fatalf("AtomicWrite falló: %v", err)
	}

	// 1. Validar que el archivo final existe y tiene el contenido correcto
	readContent, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("Fallo al leer el archivo escrito: %v", err)
	}
	if string(readContent) != string(content) {
		t.Errorf("Contenido escrito = %q; se esperaba %q", string(readContent), string(content))
	}

	// 2. Validar que el archivo temporal único (.tmp-*) fue renombrado/eliminado
	leftovers, err := filepath.Glob(filepath.Join(tmpDir, "*.tmp-*"))
	if err != nil {
		t.Fatalf("Fallo listando temporales: %v", err)
	}
	if len(leftovers) != 0 {
		t.Errorf("Quedaron %d archivos temporales sin limpiar: %v", len(leftovers), leftovers)
	}
}

func TestAtomicWriteFileMode(t *testing.T) {
	// El modo de archivo es parte del contrato de despliegue (enmienda A, R4-006):
	// los overlays deben ser legibles por Caddy, que corre como UID 1337.
	tmpDir, err := os.MkdirTemp("", "caddy-waf-test-*")
	if err != nil {
		t.Fatalf("Fallo al crear directorio temporal: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }() // Limpieza al finalizar

	targetPath := filepath.Join(tmpDir, "overlay.conf")

	// Ejecutar la escritura atómica
	err = files.AtomicWrite(targetPath, []byte("SecRuleEngine On"))
	if err != nil {
		t.Fatalf("AtomicWrite falló: %v", err)
	}

	// Validar que el archivo final es world-readable (0644)
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("Fallo al obtener el estado del archivo escrito: %v", err)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Errorf("Modo del archivo escrito = %o; se esperaba 0644", got)
	}
}

// TestAtomicWriteCleansTempOnError: si el rename falla (destino es un
// directorio), el temporal único debe eliminarse en lugar de quedar stale.
func TestAtomicWriteCleansTempOnError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "caddy-waf-test-*")
	if err != nil {
		t.Fatalf("Fallo al crear directorio temporal: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }() // Limpieza al finalizar

	// Apuntar el destino contra un directorio existente: CreateTemp y la
	// escritura funcionan, pero el rename falla (EISDIR) y el temporal debe
	// limpiarse.
	targetDir := filepath.Join(tmpDir, "target")
	if err := os.MkdirAll(targetDir, 0750); err != nil {
		t.Fatalf("Fallo al crear subdirectorio: %v", err)
	}

	if err := files.AtomicWrite(targetDir, []byte("x")); err == nil {
		t.Fatal("AtomicWrite contra un directorio debe fallar")
	}

	leftovers, err := filepath.Glob(filepath.Join(tmpDir, "*.tmp-*"))
	if err != nil {
		t.Fatalf("Fallo listando temporales: %v", err)
	}
	if len(leftovers) != 0 {
		t.Errorf("Un write fallido dejó %d temporales stale: %v", len(leftovers), leftovers)
	}
}
