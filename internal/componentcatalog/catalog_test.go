package componentcatalog

import (
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/version"
)

func TestMihomoCatalogContainsVerifiedLinuxTargets(t *testing.T) {
	for _, platform := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}} {
		asset, ok := Mihomo(platform[0], platform[1])
		if !ok || asset.Version == "" || asset.Name == "" || !strings.HasPrefix(asset.URL, "https://github.com/MetaCubeX/mihomo/releases/download/") || len(asset.SHA256) != 64 {
			t.Fatalf("Mihomo(%q, %q) = %#v, %v", platform[0], platform[1], asset, ok)
		}
	}
	if _, ok := Mihomo("darwin", "amd64"); ok {
		t.Fatal("unsupported platform unexpectedly has a Mihomo target")
	}
}

func TestSpeedtesterCatalogFollowsBackendVersion(t *testing.T) {
	asset, checksumURL, ok := Speedtester("linux", "amd64")
	if !ok || asset.Version != version.Version || !strings.Contains(asset.URL, "/v"+version.Version+"/") || !strings.HasSuffix(checksumURL, "/checksums.txt") {
		t.Fatalf("Speedtester target = %#v, checksum = %q, supported = %v", asset, checksumURL, ok)
	}
	if _, _, ok := Speedtester("darwin", "amd64"); ok {
		t.Fatal("unsupported speedtester platform unexpectedly has a target")
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		left  string
		right string
		want  int
	}{
		{"0.6.7", "0.6.8", -1},
		{"v1.19.29", "1.19.29", 0},
		{"1.2.0", "1.1.99", 1},
		{"1.2", "1.2.0", 0},
	}
	for _, test := range tests {
		if got := VersionCompare(test.left, test.right); got != test.want {
			t.Fatalf("VersionCompare(%q, %q) = %d, want %d", test.left, test.right, got, test.want)
		}
	}
}
