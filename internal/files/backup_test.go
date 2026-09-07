package files_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
)

// TestBackupWildcardSlug verifies the fix for bug #265:
// the directory and the source file must use the normalized slug,
// never the raw domain (a literal "*" cannot be part of a safe path).
func TestBackupWildcardSlug(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	// The real source file is generated as waf-{slug}.conf (see WAFConfigPath).
	sourcePath := filepath.Join(managedDir, "waf-wildcard_example_com.conf")
	content := []byte("# domain: *.example.com | mode: On | updated: 2026-07-22T14:00:00Z\n")
	if err := os.WriteFile(sourcePath, content, 0640); err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}

	if err := files.Backup("*.example.com", "waf"); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// The backup must live in the slug-normalized directory.
	slugDir := filepath.Join(backupDir, "wildcard_example_com")
	entries, err := os.ReadDir(slugDir)
	if err != nil {
		t.Fatalf("backup directory with slug %q not found: %v", slugDir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 snapshot in %q, found %d", slugDir, len(entries))
	}

	// A directory with the raw domain must never exist.
	rawDir := filepath.Join(backupDir, "*.example.com")
	if _, err := os.Stat(rawDir); !os.IsNotExist(err) {
		t.Errorf("a backup directory with the raw domain %q must not exist (bug #265)", rawDir)
	}
}

// TestBackupRetention verifies that CADDY_UI_BACKUP_KEEP is honored:
// when the limit is exceeded, the oldest snapshots of the same type are
// removed.
func TestBackupRetention(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)
	t.Setenv("CADDY_UI_BACKUP_KEEP", "1")

	sourcePath := filepath.Join(managedDir, "waf-api_example_com.conf")
	if err := os.WriteFile(sourcePath, []byte("# domain: api.example.com\n"), 0640); err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}

	// Seed two previous snapshots of the same type (alphabetical order =
	// chronological).
	slugDir := filepath.Join(backupDir, "api_example_com")
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("failed to create slugDir: %v", err)
	}
	old := []string{
		"2020-01-01T00-00-00Z.waf.conf",
		"2021-01-01T00-00-00Z.waf.conf",
	}
	for _, name := range old {
		if err := os.WriteFile(filepath.Join(slugDir, name), []byte("v"), 0640); err != nil {
			t.Fatalf("failed to seed snapshot %s: %v", name, err)
		}
	}

	if err := files.Backup("api.example.com", "waf"); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	entries, err := os.ReadDir(slugDir)
	if err != nil {
		t.Fatalf("failed to read the backups directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("retention with KEEP=1: expected 1 snapshot, found %d", len(entries))
	}
	// The surviving snapshot must be the newly created one, not the seeded ones.
	if entries[0].Name() == old[0] || entries[0].Name() == old[1] {
		t.Errorf("retention left a seeded snapshot (%s) instead of the newest one", entries[0].Name())
	}
	// The snapshot created now must carry the current timestamp (ISO8601
	// format with ":" replaced).
	if got := entries[0].Name(); got != time.Now().UTC().Format("2006-01-02T15-04-05Z")+".waf.conf" {
		t.Errorf("snapshot name = %q; expected the {ISO8601}.waf.conf format", got)
	}
}

// TestBackupSourceStatErrorReturnsError: a stat error other than IsNotExist
// (e.g. ENOTDIR because managedDir is a file) must be propagated, not treated
// as "nothing to back up" (finding J1).
func TestBackupSourceStatErrorReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	managedAsFile := filepath.Join(tmpDir, "managed-es-un-archivo")
	if err := os.WriteFile(managedAsFile, []byte("x"), 0640); err != nil {
		t.Fatalf("failed to seed file: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedAsFile)
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	if err := files.Backup("example.com", "waf"); err == nil {
		t.Fatal("Backup with a failed stat (ENOTDIR) must return an error")
	}
}

// TestBackupRetentionIgnoresNonCanonical: retention uses the same strict
// regex as ListBackups - a file that merely "contains" .waf.conf but does not
// follow the canonical format does not count toward the limit nor get
// removed.
func TestBackupRetentionIgnoresNonCanonical(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)
	t.Setenv("CADDY_UI_BACKUP_KEEP", "1")

	sourcePath := filepath.Join(managedDir, "waf-example_com.conf")
	if err := os.WriteFile(sourcePath, []byte("# domain: example.com\n"), 0640); err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}

	slugDir := filepath.Join(backupDir, "example_com")
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("failed to create slugDir: %v", err)
	}
	// Three canonical snapshots + a non-canonical name that a strings.Contains
	// would have counted (and removed) by mistake.
	for _, name := range []string{
		"2020-01-01T00-00-00Z.waf.conf",
		"2020-01-02T00-00-00Z.waf.conf",
		"2020-01-03T00-00-00Z.waf.conf",
		"notas.waf.conf.txt",
	} {
		if err := os.WriteFile(filepath.Join(slugDir, name), []byte("v"), 0640); err != nil {
			t.Fatalf("failed to seed %s: %v", name, err)
		}
	}

	if err := files.Backup("example.com", "waf"); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// KEEP=1: the non-canonical file must survive retention.
	if _, err := os.Stat(filepath.Join(slugDir, "notas.waf.conf.txt")); err != nil {
		t.Errorf("the non-canonical file must survive retention: %v", err)
	}
	entries, err := os.ReadDir(slugDir)
	if err != nil {
		t.Fatalf("failed to read slugDir: %v", err)
	}
	// 1 canonical (the newly created) + 1 non-canonical.
	if len(entries) != 2 {
		t.Fatalf("KEEP=1 with a non-canonical file: expected 2 files, got %d", len(entries))
	}
}

// seedSnapshot seeds a snapshot file in the backups directory of the slug.
func seedSnapshot(t *testing.T, backupDir, domainName, name, content string) {
	t.Helper()
	slugDir := filepath.Join(backupDir, domain.DomainSlug(domainName))
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("failed to create slugDir %q: %v", slugDir, err)
	}
	if err := os.WriteFile(filepath.Join(slugDir, name), []byte(content), 0640); err != nil {
		t.Fatalf("failed to seed snapshot %s: %v", name, err)
	}
}

// TestListBackupsSortedNewestFirst: ListBackups returns the domain snapshots
// ordered from newest to oldest, with the real size, and ignores files that
// do not follow the {ISO8601}.{type}.conf pattern.
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
		t.Fatalf("ListBackups failed: %v", err)
	}
	if len(backups) != 3 {
		t.Fatalf("expected 3 snapshots (the .txt does not count), got %d", len(backups))
	}

	// Order: newest to oldest (the hyphenated ISO sorts lexicographically).
	if backups[0].Timestamp != "2021-01-01T00-00-00Z" || backups[0].FileType != "waf" {
		t.Errorf("the first must be the 2021 waf, got %+v", backups[0])
	}
	if backups[1].FileType != "exclusions" {
		t.Errorf("the second must be the 2021 exclusions, got %+v", backups[1])
	}
	if backups[2].Timestamp != "2020-01-01T00-00-00Z" || backups[2].FileType != "waf" {
		t.Errorf("the last must be the 2020 waf, got %+v", backups[2])
	}

	// The size must be the real one of the file.
	if backups[0].Size != int64(len("waf-2021")) {
		t.Errorf("size of snapshot waf-2021 = %d; expected %d", backups[0].Size, len("waf-2021"))
	}
}

// TestListBackupsEmptyDirReturnsEmpty: with no backups directory (or empty)
// the listing returns an empty list, not an error (honest empty state in the
// UI).
func TestListBackupsEmptyDirReturnsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups")) // does not exist yet

	backups, err := files.ListBackups("api.example.com")
	if err != nil {
		t.Fatalf("ListBackups without a directory must return an empty list without error, got: %v", err)
	}
	if len(backups) != 0 {
		t.Errorf("without backups: expected an empty list, got %d", len(backups))
	}
}

// TestRestoreBackupWritesBytesToConfPath: RestoreBackup copies the bytes of
// the chosen snapshot over the overlay of the corresponding type (waf →
// waf-{slug}.conf).
func TestRestoreBackupWritesBytesToConfPath(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	snapContent := "# domain: api.example.com | mode: Off\n(snippet restaurado)\n"
	seedSnapshot(t, backupDir, "api.example.com", "2020-01-01T00-00-00Z.waf.conf", snapContent)

	if err := files.RestoreBackup("api.example.com", "2020-01-01T00-00-00Z.waf.conf"); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(managedDir, "waf-api_example_com.conf"))
	if err != nil {
		t.Fatalf("the overlay waf-api_example_com.conf was not written: %v", err)
	}
	if string(got) != snapContent {
		t.Errorf("the overlay must contain exactly the snapshot bytes:\n%s", got)
	}
}

// TestRestoreBackupRejectsUnsafeNames: names with path separators, unknown
// types or without the exact format must be rejected without writing
// anything.
func TestRestoreBackupRejectsUnsafeNames(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	for _, bad := range []string{
		"",                                  // empty
		"../evil.conf",                      // path traversal
		"/etc/passwd",                       // absolute path
		"2020-01-01T00-00-00Z",              // missing extension
		"2020-01-01T00-00-00Z.unknown.conf", // unsupported type
		"2020-01-01T00:00:00Z.waf.conf",     // ISO format with ":" (not a snapshot name)
	} {
		if err := files.RestoreBackup("api.example.com", bad); err == nil {
			t.Errorf("RestoreBackup(%q) must be rejected", bad)
		}
	}

	// No file must have been written with invalid names.
	if _, err := os.Stat(filepath.Join(managedDir, "waf-api_example_com.conf")); !os.IsNotExist(err) {
		t.Errorf("the overlay must not be written with invalid snapshot names")
	}
}

// TestRestoreBackupMissingSnapshotFails: a valid name but no file (deleted or
// nonexistent) must fail with an error and write nothing.
func TestRestoreBackupMissingSnapshotFails(t *testing.T) {
	tmpDir := t.TempDir()
	managedDir := filepath.Join(tmpDir, "ui-managed")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("failed to create managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", filepath.Join(tmpDir, "backups"))

	if err := files.RestoreBackup("api.example.com", "2099-01-01T00-00-00Z.waf.conf"); err == nil {
		t.Fatal("RestoreBackup of a nonexistent snapshot must fail")
	}
	if _, err := os.Stat(filepath.Join(managedDir, "waf-api_example_com.conf")); !os.IsNotExist(err) {
		t.Errorf("the overlay must not be written if the snapshot does not exist")
	}
}

// TestBackupTypeParsesValidNames: BackupType extracts the overlay type of a
// valid snapshot name (the three managed types).
func TestBackupTypeParsesValidNames(t *testing.T) {
	cases := []struct{ name, want string }{
		{"2026-08-07T15-52-13Z.waf.conf", "waf"},
		{"2026-08-07T15-52-13Z.exclusions.conf", "exclusions"},
		{"2026-08-07T15-52-13Z.ip-rules.conf", "ip-rules"},
	}
	for _, tc := range cases {
		got, err := files.BackupType(tc.name)
		if err != nil {
			t.Errorf("BackupType(%q) failed: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("BackupType(%q) = %q; expected %q", tc.name, got, tc.want)
		}
	}
}

// TestBackupTypeRejectsUnsafeNames: unsafe or malformed names must yield an
// error (never a valid type).
func TestBackupTypeRejectsUnsafeNames(t *testing.T) {
	for _, bad := range []string{
		"",                                  // empty
		"../evil.conf",                      // path traversal
		"etc/passwd",                        // relative subdirectory
		"2020-01-01T00-00-00Z",              // missing extension
		"2020-01-01T00-00-00Z.waf",          // missing .conf
		"2020-01-01T00-00-00Z.txt.conf",     // unknown type
		"2020-01-01T00:00:00Z.waf.conf",     // ISO with ":" (broken convention)
		"2020-01-01T00-00-00Z.waf.conf.bak", // extra suffix
	} {
		if _, err := files.BackupType(bad); err == nil {
			t.Errorf("BackupType(%q) must be rejected", bad)
		}
	}
}
