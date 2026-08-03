package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxSelfUpdateAssetBytes    int64 = 256 << 20
	maxSelfUpdateChecksumBytes int64 = 2 << 20
)

// ErrSelfUpdateRestartRequired means that a verified update has replaced (or,
// on Windows, has been scheduled to replace) this executable. The caller must
// stop this process so the replacement can be started.
var ErrSelfUpdateRestartRequired = errors.New("speedtester update applied; restart required")

var (
	selfUpdateExecutable = os.Executable
	selfUpdateReplace    = replaceSelfExecutable
)

// applySelfUpdate downloads the exact release asset announced by the control
// plane, verifies it against that release's checksums file, and replaces this
// executable when targetVersion is newer than the running version.
//
// It deliberately does not use a moving "latest" URL. The caller must exit
// when ErrSelfUpdateRestartRequired is returned; otherwise an updated binary
// cannot take effect and Windows cannot finish its deferred replacement.
func applySelfUpdate(ctx context.Context, targetVersion, assetName, downloadURL, checksumsURL string) error {
	shouldUpdate, err := speedtesterUpdateNeeded(version, targetVersion)
	if err != nil {
		return err
	}
	if !shouldUpdate {
		return nil
	}
	if err := validateUpdateTarget(assetName, downloadURL, checksumsURL); err != nil {
		return err
	}

	client := selfUpdateHTTPClient()
	expectedChecksum, err := downloadExpectedChecksum(ctx, client, checksumsURL, assetName)
	if err != nil {
		return err
	}

	executable, err := selfUpdateExecutable()
	if err != nil {
		return fmt.Errorf("locate running executable: %w", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return fmt.Errorf("resolve running executable path: %w", err)
	}

	tempPath, err := downloadUpdateAsset(ctx, client, downloadURL, executable, expectedChecksum)
	if err != nil {
		return err
	}
	if err := selfUpdateReplace(tempPath, executable); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return ErrSelfUpdateRestartRequired
}

func speedtesterUpdateNeeded(currentVersion, targetVersion string) (bool, error) {
	comparison, err := compareSpeedtesterVersions(currentVersion, targetVersion)
	if err != nil {
		return false, err
	}
	return comparison < 0, nil
}

// compareSpeedtesterVersions compares dotted numeric release versions. A
// leading v is accepted because GitHub release tags conventionally include it.
func compareSpeedtesterVersions(currentVersion, targetVersion string) (int, error) {
	current, err := parseSpeedtesterVersion(currentVersion)
	if err != nil {
		return 0, fmt.Errorf("invalid current speedtester version %q: %w", currentVersion, err)
	}
	target, err := parseSpeedtesterVersion(targetVersion)
	if err != nil {
		return 0, fmt.Errorf("invalid target speedtester version %q: %w", targetVersion, err)
	}
	length := len(current)
	if len(target) > length {
		length = len(target)
	}
	for index := 0; index < length; index++ {
		var left, right uint64
		if index < len(current) {
			left = current[index]
		}
		if index < len(target) {
			right = target[index]
		}
		switch {
		case left < right:
			return -1, nil
		case left > right:
			return 1, nil
		}
	}
	return 0, nil
}

func parseSpeedtesterVersion(raw string) ([]uint64, error) {
	value := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if value == "" {
		return nil, errors.New("empty version")
	}
	parts := strings.Split(value, ".")
	parsed := make([]uint64, len(parts))
	for index, part := range parts {
		if part == "" {
			return nil, errors.New("empty version segment")
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return nil, fmt.Errorf("non-numeric version segment %q", part)
			}
		}
		for _, character := range part {
			parsed[index] = parsed[index]*10 + uint64(character-'0')
			if parsed[index] < uint64(character-'0') {
				return nil, fmt.Errorf("version segment %q overflows", part)
			}
		}
	}
	return parsed, nil
}

func validateUpdateTarget(assetName, downloadURL, checksumsURL string) error {
	if assetName == "" || filepath.Base(assetName) != assetName || strings.ContainsAny(assetName, "\\/\x00") {
		return fmt.Errorf("invalid update asset name %q", assetName)
	}
	assetURL, err := validateUpdateSourceURL(downloadURL)
	if err != nil {
		return fmt.Errorf("invalid update download URL: %w", err)
	}
	if filepath.Base(assetURL.Path) != assetName {
		return fmt.Errorf("update download URL does not name asset %q", assetName)
	}
	if _, err := validateUpdateSourceURL(checksumsURL); err != nil {
		return fmt.Errorf("invalid update checksums URL: %w", err)
	}
	return nil
}

func validateUpdateSourceURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("scheme must be https")
	}
	if parsed.Hostname() == "" {
		return nil, errors.New("missing host")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("credentials and fragments are not allowed")
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("http is allowed only for loopback test servers")
	}
	if parsed.Scheme == "https" && !isGitHubReleaseHost(parsed.Hostname()) {
		return nil, errors.New("update source must be hosted by GitHub")
	}
	return parsed, nil
}

func validateUpdateRedirectURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	if parsed.Scheme != "https" || !isGitHubReleaseHost(parsed.Hostname()) || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("update redirect is not a trusted GitHub release host")
	}
	return nil
}

func isGitHubReleaseHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	switch host {
	case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com":
		return true
	default:
		return false
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func selfUpdateHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			return validateUpdateRedirectURL(request.URL.String())
		},
	}
}

func downloadExpectedChecksum(ctx context.Context, client *http.Client, checksumsURL, assetName string) (string, error) {
	response, err := newSelfUpdateRequest(ctx, client, checksumsURL)
	if err != nil {
		return "", fmt.Errorf("download update checksums: %w", err)
	}
	defer response.Body.Close()
	if response.ContentLength > maxSelfUpdateChecksumBytes {
		return "", fmt.Errorf("update checksums exceed %d bytes", maxSelfUpdateChecksumBytes)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, maxSelfUpdateChecksumBytes+1))
	if err != nil {
		return "", fmt.Errorf("read update checksums: %w", err)
	}
	if int64(len(contents)) > maxSelfUpdateChecksumBytes {
		return "", fmt.Errorf("update checksums exceed %d bytes", maxSelfUpdateChecksumBytes)
	}
	checksum, err := checksumForUpdateAsset(string(contents), assetName)
	if err != nil {
		return "", fmt.Errorf("find checksum for %s: %w", assetName, err)
	}
	return checksum, nil
}

func newSelfUpdateRequest(ctx context.Context, client *http.Client, rawURL string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("unexpected HTTP status %s", response.Status)
	}
	return response, nil
}

func checksumForUpdateAsset(contents, assetName string) (string, error) {
	var found string
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		checksum, fileName, ok := parseChecksumLine(line)
		if !ok || fileName != assetName {
			continue
		}
		if found != "" && found != checksum {
			return "", errors.New("conflicting checksums for asset")
		}
		found = checksum
	}
	if found == "" {
		return "", errors.New("asset is absent from checksums file")
	}
	return found, nil
}

func parseChecksumLine(line string) (checksum, fileName string, ok bool) {
	if strings.HasPrefix(line, "SHA256 (") {
		const separator = ") = "
		end := strings.Index(line, separator)
		if end > len("SHA256 (") {
			fileName = line[len("SHA256 ("):end]
			checksum = strings.TrimSpace(line[end+len(separator):])
			return checksum, fileName, validSHA256(checksum)
		}
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !validSHA256(fields[0]) {
		return "", "", false
	}
	fileName = strings.TrimPrefix(strings.Join(fields[1:], " "), "*")
	return fields[0], fileName, true
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func downloadUpdateAsset(ctx context.Context, client *http.Client, downloadURL, executable, expectedChecksum string) (string, error) {
	response, err := newSelfUpdateRequest(ctx, client, downloadURL)
	if err != nil {
		return "", fmt.Errorf("download update asset: %w", err)
	}
	defer response.Body.Close()
	if response.ContentLength > maxSelfUpdateAssetBytes {
		return "", fmt.Errorf("update asset exceeds %d bytes", maxSelfUpdateAssetBytes)
	}

	directory := filepath.Dir(executable)
	temporary, err := os.CreateTemp(directory, ".relaydock-speedtester-update-*")
	if err != nil {
		return "", fmt.Errorf("create update temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func(err error) (string, error) {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
		return "", err
	}

	info, err := os.Stat(executable)
	if err != nil {
		return cleanup(fmt.Errorf("stat running executable: %w", err))
	}
	mode := info.Mode().Perm() | 0o111
	if err := temporary.Chmod(mode); err != nil {
		return cleanup(fmt.Errorf("set update executable mode: %w", err))
	}

	hash := sha256.New()
	reader := io.LimitReader(response.Body, maxSelfUpdateAssetBytes+1)
	bytesWritten, err := io.Copy(io.MultiWriter(temporary, hash), reader)
	if err != nil {
		return cleanup(fmt.Errorf("write update asset: %w", err))
	}
	if bytesWritten > maxSelfUpdateAssetBytes {
		return cleanup(fmt.Errorf("update asset exceeds %d bytes", maxSelfUpdateAssetBytes))
	}
	actualChecksum := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actualChecksum, expectedChecksum) {
		return cleanup(fmt.Errorf("update checksum mismatch: got %s", actualChecksum))
	}
	if err := temporary.Sync(); err != nil {
		return cleanup(fmt.Errorf("sync update asset: %w", err))
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return "", fmt.Errorf("close update asset: %w", err)
	}
	return temporaryPath, nil
}
