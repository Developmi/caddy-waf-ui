package files

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// ErrInvalidBackup señala un nombre de snapshot inválido o inexistente. Los
// handlers REST lo traducen a 400 Bad Request (mismo patrón que ErrInvalidMode).
var ErrInvalidBackup = errors.New("snapshot de configuración inválido")

// backupNamePattern valida el nombre canónico de un snapshot:
// {ISO8601 UTC con :→-}.{tipo}.conf - ej: 2026-08-07T15-52-13Z.waf.conf.
// El patrón estricto (timestamp de 20 caracteres + tipo conocido) impide
// path traversal y cualquier nombre fuera de la convención de backup.
// El conjunto de tipos se construye desde las constantes FileType* (J5-7)
// para que regex y switches nunca divergan.
var backupNamePattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)\.(` +
	FileTypeWAF + `|` + FileTypeExclusions + `|` + FileTypeIPRules + `)\.conf$`)

// BackupType valida el nombre de un snapshot y devuelve el tipo de overlay al
// que pertenece ("waf" | "exclusions" | "ip-rules"). Rechaza nombres con
// separadores de ruta o fuera del formato canónico (anti path traversal).
func BackupType(snapshotID string) (string, error) {
	m := backupNamePattern.FindStringSubmatch(snapshotID)
	if m == nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidBackup, snapshotID)
	}
	return m[2], nil
}

// ListBackups devuelve los snapshots de configuración de un dominio ordenados
// del más reciente al más antiguo. Los archivos que no siguen la convención de
// nombres se ignoran; sin directorio de backups devuelve lista vacía (estado
// vacío honesto, nunca un error).
func ListBackups(domainName string) ([]BackupInfo, error) {
	entries, err := os.ReadDir(BackupDirPath(backupDirPath(), domainName))
	if os.IsNotExist(err) {
		return []BackupInfo{}, nil
	}
	if err != nil {
		return nil, err
	}

	backups := make([]BackupInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		m := backupNamePattern.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		backups = append(backups, BackupInfo{Timestamp: m[1], FileType: m[2], Size: info.Size()})
	}

	// El ISO8601 con guiones ordena lexicográficamente = cronológicamente:
	// descendente deja el snapshot más reciente primero.
	sort.Slice(backups, func(i, j int) bool {
		keyI := backups[i].Timestamp + backups[i].FileType
		keyJ := backups[j].Timestamp + backups[j].FileType
		return keyI > keyJ
	})

	return backups, nil
}

// RestoreBackup restaura los bytes del snapshot indicado (nombre completo
// {ISO8601}.{tipo}.conf) sobre el overlay de su tipo con escritura atómica
// (bytes → conf path). Falla si el nombre es inválido o el snapshot no existe.
func RestoreBackup(domainName, snapshotID string) error {
	fileType, err := BackupType(snapshotID)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(filepath.Join(BackupDirPath(backupDirPath(), domainName), snapshotID))
	if os.IsNotExist(err) {
		return fmt.Errorf("%w: el snapshot %q no existe", ErrInvalidBackup, snapshotID)
	}
	if err != nil {
		return err
	}

	confPath, err := OverlayPath(managedDirPath(), fileType, domainName)
	if err != nil {
		return err
	}
	return AtomicWrite(confPath, content)
}

// BackupInfo describe un snapshot de configuración disponible para rollback.
// La Fase 4 completa la lectura (ListBackups/RestoreBackup); la UI ya consume
// el shape para renderizar el historial (rollback.html).
type BackupInfo struct {
	Timestamp string
	FileType  string
	Size      int64
}

// managedDirPath devuelve el directorio de overlays gestionados. Centralizado
// en config (hallazgo J5-3): antes vivía triplicado en chain.go, backup.go y
// pages.go con la misma lectura de entorno.
func managedDirPath() string {
	return config.ManagedDir()
}

// backupDirPath devuelve el directorio raíz de snapshots.
func backupDirPath() string {
	return config.BackupDir()
}

// Backup toma el estado actual de un archivo de configuración de un dominio y crea un snapshot.
// Respeta el límite de retención definido en las variables de entorno[cite: 4].
func Backup(domainName string, fileType string) error {
	// 1. Definir rutas basadas en las variables de entorno
	managedDir := managedDirPath()
	backupDir := backupDirPath()

	keepLimit := config.BackupKeep()

	// Archivo origen en /ui-managed/
	// Ej: waf-api_example_com.conf
	// El slug se usa tanto para el origen como para el directorio de backups (bug #265):
	// el dominio crudo con comodín ("*") no puede formar parte de una ruta.
	sourceFileName := fmt.Sprintf("%s-%s.conf", fileType, domain.DomainSlug(domainName))
	sourcePath := filepath.Join(managedDir, sourceFileName)

	// Si el archivo origen no existe, no hay nada que respaldar (ej: primera
	// vez que se configura). Cualquier otro error de stat (p.ej. EACCES) es un
	// fallo real y debe propagarse, no tratarse como "sin backup previo".
	if _, err := os.Stat(sourcePath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("error comprobando el archivo origen %q: %w", sourcePath, err)
	}

	// 2. Crear el directorio de backup para este dominio
	domainBackupDir := BackupDirPath(backupDir, domainName)
	if err := os.MkdirAll(domainBackupDir, 0750); err != nil {
		return fmt.Errorf("error creando directorio de backup: %w", err)
	}

	// 3. Generar el snapshot con formato {ISO8601}.{fileType}.conf[cite: 1]
	// Usamos formato seguro para nombres de archivo (reemplazando : por -)
	timestamp := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	backupFileName := fmt.Sprintf("%s.%s.conf", timestamp, fileType)
	backupPath := filepath.Join(domainBackupDir, backupFileName)

	if err := copyFile(sourcePath, backupPath); err != nil {
		return fmt.Errorf("error copiando backup: %w", err)
	}

	// 4. Aplicar política de retención (Limpiar backups antiguos)
	return enforceRetention(domainBackupDir, fileType, keepLimit)
}

// copyFile es una función auxiliar para copiar los bytes de un archivo a otro
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = sourceFile.Close() }()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = destFile.Close() }()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// enforceRetention elimina los snapshots más antiguos si se supera el límite
func enforceRetention(dir, fileType string, limit int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	// Filtrar solo los snapshots canónicos de este tipo específico (waf,
	// exclusions, ip-rules): misma regex estricta que ListBackups, para que
	// la retención y el listado coincidan en qué cuenta como backup.
	var backups []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		m := backupNamePattern.FindStringSubmatch(entry.Name())
		if m == nil || m[2] != fileType {
			continue
		}
		backups = append(backups, entry)
	}

	// Si estamos dentro del límite, no hacemos nada
	if len(backups) <= limit {
		return nil
	}

	// Ordenar alfabéticamente (por cómo construimos el ISO8601, el orden alfabético es cronológico)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Name() < backups[j].Name()
	})

	// Eliminar los más antiguos
	toDelete := len(backups) - limit
	for i := 0; i < toDelete; i++ {
		oldPath := filepath.Join(dir, backups[i].Name())
		if err := os.Remove(oldPath); err != nil {
			return fmt.Errorf("error eliminando backup antiguo %s: %w", oldPath, err)
		}
	}

	return nil
}
