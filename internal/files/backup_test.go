package files_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
)

// TestBackupWildcardSlug verifica la corrección del bug #265:
// el directorio y el archivo origen deben usar el slug normalizado,
// nunca el dominio crudo (un "*" literal no puede formar parte de una ruta segura).
func TestBackupWildcardSlug(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("Fallo al crear managedDir: %v", err)
	}

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	// El archivo origen real se genera como waf-{slug}.conf (ver WAFConfigPath).
	sourcePath := filepath.Join(managedDir, "waf-wildcard_example_com.conf")
	content := []byte("# domain: *.example.com | mode: On | updated: 2026-07-22T14:00:00Z\n")
	if err := os.WriteFile(sourcePath, content, 0640); err != nil {
		t.Fatalf("Fallo al crear archivo origen: %v", err)
	}

	if err := files.Backup("*.example.com", "waf"); err != nil {
		t.Fatalf("Backup falló: %v", err)
	}

	// El backup debe vivir en el directorio con slug normalizado.
	slugDir := filepath.Join(backupDir, "wildcard_example_com")
	entries, err := os.ReadDir(slugDir)
	if err != nil {
		t.Fatalf("No se encontró el directorio de backup con slug %q: %v", slugDir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("Se esperaba 1 snapshot en %q, se encontraron %d", slugDir, len(entries))
	}

	// Nunca debe existir un directorio con el dominio crudo.
	rawDir := filepath.Join(backupDir, "*.example.com")
	if _, err := os.Stat(rawDir); !os.IsNotExist(err) {
		t.Errorf("No debe existir un directorio de backup con el dominio crudo %q (bug #265)", rawDir)
	}
}

// TestBackupRetention verifica que se respete CADDY_UI_BACKUP_KEEP:
// al superar el límite se eliminan los snapshots más antiguos del mismo tipo.
func TestBackupRetention(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("Fallo al crear managedDir: %v", err)
	}

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)
	t.Setenv("CADDY_UI_BACKUP_KEEP", "1")

	sourcePath := filepath.Join(managedDir, "waf-api_example_com.conf")
	if err := os.WriteFile(sourcePath, []byte("# domain: api.example.com\n"), 0640); err != nil {
		t.Fatalf("Fallo al crear archivo origen: %v", err)
	}

	// Sembrar dos snapshots previos del mismo tipo (orden alfabético = cronológico).
	slugDir := filepath.Join(backupDir, "api_example_com")
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("Fallo al crear slugDir: %v", err)
	}
	old := []string{
		"2020-01-01T00-00-00Z.waf.conf",
		"2021-01-01T00-00-00Z.waf.conf",
	}
	for _, name := range old {
		if err := os.WriteFile(filepath.Join(slugDir, name), []byte("v"), 0640); err != nil {
			t.Fatalf("Fallo al sembrar snapshot %s: %v", name, err)
		}
	}

	if err := files.Backup("api.example.com", "waf"); err != nil {
		t.Fatalf("Backup falló: %v", err)
	}

	entries, err := os.ReadDir(slugDir)
	if err != nil {
		t.Fatalf("Fallo al leer el directorio de backups: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Retención con KEEP=1: se esperaba 1 snapshot, se encontraron %d", len(entries))
	}
	// El snapshot sobreviviente debe ser el recién creado, no los sembrados.
	if entries[0].Name() == old[0] || entries[0].Name() == old[1] {
		t.Errorf("La retención dejó un snapshot sembrado (%s) en lugar del más nuevo", entries[0].Name())
	}
	// El snapshot creado ahora debe llevar la marca de tiempo actual (formato ISO8601 con ":" reemplazado).
	if got := entries[0].Name(); got != time.Now().UTC().Format("2006-01-02T15-04-05Z")+".waf.conf" {
		t.Errorf("Nombre del snapshot = %q; se esperaba el formato {ISO8601}.waf.conf", got)
	}
}

// TestBackupSourceStatErrorReturnsError: un error de stat distinto de
// IsNotExist (p.ej. ENOTDIR porque managedDir es un archivo) debe propagarse,
// no tratarse como "nada que respaldar" (hallazgo J1).
func TestBackupSourceStatErrorReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	managedAsFile := filepath.Join(tmpDir, "managed-es-un-archivo")
	if err := os.WriteFile(managedAsFile, []byte("x"), 0640); err != nil {
		t.Fatalf("Fallo al sembrar archivo: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedAsFile)
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	if err := files.Backup("example.com", "waf"); err == nil {
		t.Fatal("Backup con stat fallido (ENOTDIR) debe devolver error")
	}
}

// TestBackupRetentionIgnoresNonCanonical: la retención usa la misma regex
// estricta que ListBackups - un archivo que solo "contiene" .waf.conf pero no
// sigue el formato canónico no cuenta para el límite ni se elimina.
func TestBackupRetentionIgnoresNonCanonical(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("Fallo al crear managedDir: %v", err)
	}

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)
	t.Setenv("CADDY_UI_BACKUP_KEEP", "1")

	sourcePath := filepath.Join(managedDir, "waf-example_com.conf")
	if err := os.WriteFile(sourcePath, []byte("# domain: example.com\n"), 0640); err != nil {
		t.Fatalf("Fallo al crear archivo origen: %v", err)
	}

	slugDir := filepath.Join(backupDir, "example_com")
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("Fallo al crear slugDir: %v", err)
	}
	// Tres snapshots canónicos + un nombre no canónico que un strings.Contains
	// hubiera contado (y eliminado) por error.
	for _, name := range []string{
		"2020-01-01T00-00-00Z.waf.conf",
		"2020-01-02T00-00-00Z.waf.conf",
		"2020-01-03T00-00-00Z.waf.conf",
		"notas.waf.conf.txt",
	} {
		if err := os.WriteFile(filepath.Join(slugDir, name), []byte("v"), 0640); err != nil {
			t.Fatalf("Fallo al sembrar %s: %v", name, err)
		}
	}

	if err := files.Backup("example.com", "waf"); err != nil {
		t.Fatalf("Backup falló: %v", err)
	}

	// KEEP=1: el archivo no canónico debe sobrevivir a la retención.
	if _, err := os.Stat(filepath.Join(slugDir, "notas.waf.conf.txt")); err != nil {
		t.Errorf("el archivo no canónico debe sobrevivir a la retención: %v", err)
	}
	entries, err := os.ReadDir(slugDir)
	if err != nil {
		t.Fatalf("Fallo al leer slugDir: %v", err)
	}
	// 1 canónico (el recién creado) + 1 no canónico.
	if len(entries) != 2 {
		t.Fatalf("KEEP=1 con archivo no canónico: se esperaban 2 archivos, hay %d", len(entries))
	}
}

// seedSnapshot siembra un archivo de snapshot en el directorio de backups del slug.
func seedSnapshot(t *testing.T, backupDir, domainName, name, content string) {
	t.Helper()
	slugDir := filepath.Join(backupDir, domain.DomainSlug(domainName))
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("Fallo al crear slugDir %q: %v", slugDir, err)
	}
	if err := os.WriteFile(filepath.Join(slugDir, name), []byte(content), 0640); err != nil {
		t.Fatalf("Fallo al sembrar snapshot %s: %v", name, err)
	}
}

// TestListBackupsSortedNewestFirst: ListBackups devuelve los snapshots del
// dominio ordenados del más reciente al más antiguo, con tamaño real, e ignora
// archivos que no siguen el patrón {ISO8601}.{tipo}.conf.
func TestListBackupsSortedNewestFirst(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, "backups")
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	seedSnapshot(t, backupDir, "api.example.com", "2020-01-01T00-00-00Z.waf.conf", "waf-2020")
	seedSnapshot(t, backupDir, "api.example.com", "2021-01-01T00-00-00Z.waf.conf", "waf-2021")
	seedSnapshot(t, backupDir, "api.example.com", "2021-01-01T00-00-00Z.exclusions.conf", "exc-2021")
	seedSnapshot(t, backupDir, "api.example.com", "not-a-backup.txt", "ignorado")

	backups, err := files.ListBackups("api.example.com")
	if err != nil {
		t.Fatalf("ListBackups falló: %v", err)
	}
	if len(backups) != 3 {
		t.Fatalf("Se esperaban 3 snapshots (el .txt no cuenta), se obtuvieron %d", len(backups))
	}

	// Orden: del más reciente al más antiguo (el ISO con guiones ordena lexicográfico).
	if backups[0].Timestamp != "2021-01-01T00-00-00Z" || backups[0].FileType != "waf" {
		t.Errorf("El primero debe ser el waf de 2021, se obtuvo %+v", backups[0])
	}
	if backups[1].FileType != "exclusions" {
		t.Errorf("El segundo debe ser el exclusions de 2021, se obtuvo %+v", backups[1])
	}
	if backups[2].Timestamp != "2020-01-01T00-00-00Z" || backups[2].FileType != "waf" {
		t.Errorf("El último debe ser el waf de 2020, se obtuvo %+v", backups[2])
	}

	// El tamaño debe ser el real del archivo.
	if backups[0].Size != int64(len("waf-2021")) {
		t.Errorf("Size del snapshot waf-2021 = %d; se esperaba %d", backups[0].Size, len("waf-2021"))
	}
}

// TestListBackupsEmptyDirReturnsEmpty: sin directorio de backups (o vacío) el
// listado devuelve una lista vacía, no un error (estado vacío honesto en la UI).
func TestListBackupsEmptyDirReturnsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups")) // no existe aún

	backups, err := files.ListBackups("api.example.com")
	if err != nil {
		t.Fatalf("ListBackups sin directorio debe devolver lista vacía sin error, se obtuvo: %v", err)
	}
	if len(backups) != 0 {
		t.Errorf("Sin backups se esperaba lista vacía, se obtuvieron %d", len(backups))
	}
}

// TestRestoreBackupWritesBytesToConfPath: RestoreBackup copia los bytes del
// snapshot elegido sobre el overlay del tipo correspondiente (waf → waf-{slug}.conf).
func TestRestoreBackupWritesBytesToConfPath(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("Fallo al crear managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	snapContent := "# domain: api.example.com | mode: Off\n(snippet restaurado)\n"
	seedSnapshot(t, backupDir, "api.example.com", "2020-01-01T00-00-00Z.waf.conf", snapContent)

	if err := files.RestoreBackup("api.example.com", "2020-01-01T00-00-00Z.waf.conf"); err != nil {
		t.Fatalf("RestoreBackup falló: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(managedDir, "waf-api_example_com.conf"))
	if err != nil {
		t.Fatalf("No se escribió el overlay waf-api_example_com.conf: %v", err)
	}
	if string(got) != snapContent {
		t.Errorf("El overlay debe contener exactamente los bytes del snapshot:\n%s", got)
	}
}

// TestRestoreBackupRejectsUnsafeNames: nombres con separadores de ruta, tipos
// desconocidos o sin el formato exacto deben rechazarse sin escribir nada.
func TestRestoreBackupRejectsUnsafeNames(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("Fallo al crear managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	for _, bad := range []string{
		"",                                  // vacío
		"../evil.conf",                      // path traversal
		"/etc/passwd",                       // ruta absoluta
		"2020-01-01T00-00-00Z",              // sin extensión
		"2020-01-01T00-00-00Z.unknown.conf", // tipo no soportado
		"2020-01-01T00:00:00Z.waf.conf",     // formato ISO con ":" (no es el nombre de snapshot)
	} {
		if err := files.RestoreBackup("api.example.com", bad); err == nil {
			t.Errorf("RestoreBackup(%q) debe rechazarse", bad)
		}
	}

	// Ningún archivo debe haberse escrito con nombres inválidos.
	if _, err := os.Stat(filepath.Join(managedDir, "waf-api_example_com.conf")); !os.IsNotExist(err) {
		t.Errorf("No debe escribirse el overlay con nombres de snapshot inválidos")
	}
}

// TestRestoreBackupMissingSnapshotFails: un nombre válido pero sin archivo
// (borrado o inexistente) debe fallar con error, no escribirse nada.
func TestRestoreBackupMissingSnapshotFails(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("Fallo al crear managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	if err := files.RestoreBackup("api.example.com", "2099-01-01T00-00-00Z.waf.conf"); err == nil {
		t.Fatal("RestoreBackup de un snapshot inexistente debe fallar")
	}
	if _, err := os.Stat(filepath.Join(managedDir, "waf-api_example_com.conf")); !os.IsNotExist(err) {
		t.Errorf("No debe escribirse el overlay si el snapshot no existe")
	}
}

// TestBackupTypeParsesValidNames: BackupType extrae el tipo de overlay de un
// nombre de snapshot válido (los tres tipos gestionados).
func TestBackupTypeParsesValidNames(t *testing.T) {
	cases := []struct{ name, want string }{
		{"2026-08-07T15-52-13Z.waf.conf", "waf"},
		{"2026-08-07T15-52-13Z.exclusions.conf", "exclusions"},
		{"2026-08-07T15-52-13Z.ip-rules.conf", "ip-rules"},
	}
	for _, tc := range cases {
		got, err := files.BackupType(tc.name)
		if err != nil {
			t.Errorf("BackupType(%q) falló: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("BackupType(%q) = %q; se esperaba %q", tc.name, got, tc.want)
		}
	}
}

// TestBackupTypeRejectsUnsafeNames: nombres inseguros o malformados deben dar
// error (nunca un tipo válido).
func TestBackupTypeRejectsUnsafeNames(t *testing.T) {
	for _, bad := range []string{
		"",                                  // vacío
		"../evil.conf",                      // path traversal
		"etc/passwd",                        // subdirectorio relativo
		"2020-01-01T00-00-00Z",              // sin extensión
		"2020-01-01T00-00-00Z.waf",          // sin .conf
		"2020-01-01T00-00-00Z.txt.conf",     // tipo desconocido
		"2020-01-01T00:00:00Z.waf.conf",     // ISO con ":" (convención rota)
		"2020-01-01T00-00-00Z.waf.conf.bak", // sufijo extra
	} {
		if _, err := files.BackupType(bad); err == nil {
			t.Errorf("BackupType(%q) debe rechazarse", bad)
		}
	}
}
