// Package componentcatalog contains the external component releases approved
// for a given Arcway backend build.  The catalog is intentionally compiled
// into the backend: a running control plane only installs versions that its
// own release explicitly names.
package componentcatalog

import (
	"fmt"
	"strings"

	"github.com/violetaini/relaydock/internal/version"
)

const (
	githubReleaseRoot = "https://github.com/violetaini/relaydock/releases/download"
	mihomoVersion     = "1.19.29"
	OoklaVersion      = "1.2.0"
)

// Asset is a platform-specific, immutable external binary target.
type Asset struct {
	Version string
	Name    string
	URL     string
	SHA256  string
}

// Mihomo returns the exact MetaCubeX artifact approved by this backend build.
// The source URLs and archive hashes are copied from the upstream GitHub
// release metadata when this catalog is updated.
func Mihomo(goos, goarch string) (Asset, bool) {
	switch goos + "/" + goarch {
	case "linux/amd64":
		return Asset{
			Version: mihomoVersion,
			Name:    "mihomo-linux-amd64-compatible-v1.19.29.gz",
			URL:     "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/mihomo-linux-amd64-compatible-v1.19.29.gz",
			SHA256:  "5612e698e96c8b8ad15abc4c0a4f098eba9234354b4f248cb97f2528e215b094",
		}, true
	case "linux/arm64":
		return Asset{
			Version: mihomoVersion,
			Name:    "mihomo-linux-arm64-v1.19.29.gz",
			URL:     "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/mihomo-linux-arm64-v1.19.29.gz",
			SHA256:  "9a868b5e4e0ad91d9d71e1b41b0cfce78aaba44360c30df74a723f8e3926a86c",
		}, true
	default:
		return Asset{}, false
	}
}

// Speedtester returns the RelayDock home speedtester release that matches this
// backend. The checksum file lives beside the immutable GitHub Release asset;
// clients must validate it before replacing their executable.
func Speedtester(goos, goarch string) (Asset, string, bool) {
	name := ""
	switch goos + "/" + goarch {
	case "linux/amd64":
		name = "relaydock-speedtester-linux-amd64"
	case "linux/arm64":
		name = "relaydock-speedtester-linux-arm64"
	case "windows/amd64":
		name = "relaydock-speedtester-windows-amd64.exe"
	case "windows/arm64":
		name = "relaydock-speedtester-windows-arm64.exe"
	default:
		return Asset{}, "", false
	}
	tag := "v" + version.Version
	base := fmt.Sprintf("%s/%s", githubReleaseRoot, tag)
	return Asset{
		Version: version.Version,
		Name:    name,
		URL:     base + "/" + name,
	}, base + "/checksums.txt", true
}

// VersionCompare compares dotted numeric versions. It ignores a leading v,
// treats absent segments as zero, and returns -1, 0, or 1.
func VersionCompare(left, right string) int {
	leftParts := splitVersion(left)
	rightParts := splitVersion(right)
	length := len(leftParts)
	if len(rightParts) > length {
		length = len(rightParts)
	}
	for index := 0; index < length; index++ {
		var l, r int
		if index < len(leftParts) {
			l = leftParts[index]
		}
		if index < len(rightParts) {
			r = rightParts[index]
		}
		if l < r {
			return -1
		}
		if l > r {
			return 1
		}
	}
	return 0
}

func splitVersion(raw string) []int {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ".")
	values := make([]int, 0, len(parts))
	for _, part := range parts {
		value := 0
		for _, character := range part {
			if character < '0' || character > '9' {
				break
			}
			value = value*10 + int(character-'0')
		}
		values = append(values, value)
	}
	return values
}
