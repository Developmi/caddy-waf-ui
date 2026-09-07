package domain_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// findSite looks up a site by its normalized slug by iterating the slice
// returned by Scan (the in-memory Registry was removed, finding J5-6).
func findSite(sites []*domain.Site, slug string) (*domain.Site, bool) {
	for _, site := range sites {
		if domain.DomainSlug(site.Domain) == slug {
			return site, true
		}
	}
	return nil, false
}

// TestScanRegistersSitesFromHeaders verifies that the scanner parses the
// "# domain: | mode: | updated:" header of the waf-*.conf overlays and
// returns the REAL domain (not the slug derived from the file name).
func TestScanRegistersSitesFromHeaders(t *testing.T) {
	scanner := domain.NewScanner(filepath.Join("testdata"))

	sites, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Real domain with mode and timestamp from the header.
	site, ok := findSite(sites, "api_example_com")
	if !ok {
		t.Fatal("api_example_com was not registered with the slug key")
	}
	if site.Domain != "api.example.com" {
		t.Errorf("Domain = %q; expected the real domain %q (not the slug)", site.Domain, "api.example.com")
	}
	if site.Mode != domain.ModeOn {
		t.Errorf("Mode = %q; expected %q", site.Mode, domain.ModeOn)
	}
	wantUpdated := time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)
	if !site.Updated.Equal(wantUpdated) {
		t.Errorf("Updated = %v; expected %v", site.Updated, wantUpdated)
	}

	// Wildcard: the identifier is the normalized slug (wildcard_example_com)
	// but Site.Domain keeps the real domain exactly as it comes in the header.
	wsite, ok := findSite(sites, "wildcard_example_com")
	if !ok {
		t.Fatal("wildcard_example_com was not registered as the wildcard domain identifier")
	}
	if wsite.Domain != "*.EXAMPLE.com" {
		t.Errorf("Domain = %q; expected the real domain %q", wsite.Domain, "*.EXAMPLE.com")
	}
	if wsite.Mode != domain.ModeDetectionOnly {
		t.Errorf("Mode = %q; expected %q", wsite.Mode, domain.ModeDetectionOnly)
	}
	wantWildcardUpdated := time.Date(2026, 7, 20, 9, 30, 0, 0, time.UTC)
	if !wsite.Updated.Equal(wantWildcardUpdated) {
		t.Errorf("Updated = %v; expected %v", wsite.Updated, wantWildcardUpdated)
	}

	// File without a header: skipped (not registered) and the scan continued
	// with the rest.
	if _, ok := findSite(sites, "sin_cabecera"); ok {
		t.Error("the file without a header should not have been registered")
	}

	// File that is not waf-*.conf: ignored even if it has a valid header.
	if _, ok := findSite(sites, "exclusions_example_com"); ok {
		t.Error("the exclusions-*.conf file should not have been registered")
	}

	if got := len(sites); got != 2 {
		t.Errorf("expected 2 registered sites, found %d", got)
	}
}

// seedOverlayDir prepares a temp directory with a single waf-*.conf overlay
// whose content is the given header, for isolated scanner tests.
func seedOverlayDir(t *testing.T, header string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "waf-degraded_example_com.conf"), []byte(header), 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}
	return dir
}

// TestScanRegistersDegradedSiteOnInvalidMode: an unknown mode in the header
// MUST NOT be presented as a real mode (W1): the site is registered with
// DetectionOnly (non-blocking default, forward-compat) and the Degraded flag
// stays true so the UI warns that the real state in Caddy differs.
func TestScanRegistersDegradedSiteOnInvalidMode(t *testing.T) {
	dir := seedOverlayDir(t, "# domain: degraded.example.com | mode: BlockAll | updated: 2026-08-07T00:00:00Z\n")

	sites, err := domain.NewScanner(dir).Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	site, ok := findSite(sites, "degraded_example_com")
	if !ok {
		t.Fatal("the site with an invalid mode must still be registered (not hidden)")
	}
	if site.Mode != domain.ModeDetectionOnly {
		t.Errorf("Mode = %q; expected the default %q", site.Mode, domain.ModeDetectionOnly)
	}
	if !site.Degraded {
		t.Error("Degraded must be true when the header carries an unknown mode")
	}
}

// TestScanValidModeNotDegraded (triangulation): a valid mode never marks the
// site as degraded.
func TestScanValidModeNotDegraded(t *testing.T) {
	dir := seedOverlayDir(t, "# domain: degraded.example.com | mode: On | updated: 2026-08-07T00:00:00Z\n")

	sites, err := domain.NewScanner(dir).Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	site, ok := findSite(sites, "degraded_example_com")
	if !ok {
		t.Fatal("the site was not registered")
	}
	if site.Mode != domain.ModeOn {
		t.Errorf("Mode = %q; expected %q", site.Mode, domain.ModeOn)
	}
	if site.Degraded {
		t.Error("a valid mode must not mark the site as degraded")
	}
}

// TestScanHeaderWithoutModeNotDegraded (triangulation): the absence of a mode
// in the header uses the DetectionOnly default without marking degraded -
// only a mode that is PRESENT but unknown signals desynchronization.
func TestScanHeaderWithoutModeNotDegraded(t *testing.T) {
	dir := seedOverlayDir(t, "# domain: degraded.example.com | updated: 2026-08-07T00:00:00Z\n")

	sites, err := domain.NewScanner(dir).Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	site, ok := findSite(sites, "degraded_example_com")
	if !ok {
		t.Fatal("the site was not registered")
	}
	if site.Mode != domain.ModeDetectionOnly {
		t.Errorf("Mode = %q; expected the default %q", site.Mode, domain.ModeDetectionOnly)
	}
	if site.Degraded {
		t.Error("a header without a mode must not mark the site as degraded")
	}
}

// TestScanMissingDirReturnsEmpty: a nonexistent directory is not an error:
// the scan returns an empty list (honest empty state, first start).
func TestScanMissingDirReturnsEmpty(t *testing.T) {
	sites, err := domain.NewScanner(filepath.Join(t.TempDir(), "no-existe")).Scan()
	if err != nil {
		t.Fatalf("Scan with a nonexistent directory must not fail: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("without a directory: expected an empty list, found %d sites", len(sites))
	}
}
