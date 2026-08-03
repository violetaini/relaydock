package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestApplySelfUpdateVerifiesAndReplacesExecutable(t *testing.T) {
	assetName := "relaydock-speedtester-linux-amd64"
	asset := []byte("verified speedtester update")
	checksum := sha256.Sum256(asset)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/checksums.txt":
			_, _ = writer.Write([]byte(hex.EncodeToString(checksum[:]) + "  " + assetName + "\n"))
		case "/" + assetName:
			_, _ = writer.Write(asset)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	directory := t.TempDir()
	executable := filepath.Join(directory, "relaydock-speedtester")
	if err := os.WriteFile(executable, []byte("old speedtester"), 0o755); err != nil {
		t.Fatal(err)
	}

	originalVersion := version
	originalExecutable := selfUpdateExecutable
	originalReplace := selfUpdateReplace
	version = "0.6.7"
	selfUpdateExecutable = func() (string, error) { return executable, nil }
	selfUpdateReplace = replaceSelfExecutable
	t.Cleanup(func() {
		version = originalVersion
		selfUpdateExecutable = originalExecutable
		selfUpdateReplace = originalReplace
	})

	err := applySelfUpdate(context.Background(), "0.6.8", assetName, server.URL+"/"+assetName, server.URL+"/checksums.txt")
	if !errors.Is(err, ErrSelfUpdateRestartRequired) {
		t.Fatalf("applySelfUpdate error = %v, want restart required", err)
	}
	updated, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if string(updated) != string(asset) {
		t.Fatalf("updated executable = %q, want %q", updated, asset)
	}
}

func TestApplySelfUpdateRejectsBadChecksum(t *testing.T) {
	assetName := "relaydock-speedtester-linux-amd64"
	asset := []byte("untrusted speedtester update")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/checksums.txt":
			_, _ = writer.Write([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  " + assetName + "\n"))
		case "/" + assetName:
			_, _ = writer.Write(asset)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	directory := t.TempDir()
	executable := filepath.Join(directory, "relaydock-speedtester")
	if err := os.WriteFile(executable, []byte("old speedtester"), 0o755); err != nil {
		t.Fatal(err)
	}

	originalVersion := version
	originalExecutable := selfUpdateExecutable
	originalReplace := selfUpdateReplace
	version = "0.6.7"
	selfUpdateExecutable = func() (string, error) { return executable, nil }
	selfUpdateReplace = replaceSelfExecutable
	t.Cleanup(func() {
		version = originalVersion
		selfUpdateExecutable = originalExecutable
		selfUpdateReplace = originalReplace
	})

	err := applySelfUpdate(context.Background(), "0.6.8", assetName, server.URL+"/"+assetName, server.URL+"/checksums.txt")
	if err == nil || errors.Is(err, ErrSelfUpdateRestartRequired) {
		t.Fatalf("applySelfUpdate error = %v, want checksum failure", err)
	}
	contents, readErr := os.ReadFile(executable)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(contents) != "old speedtester" {
		t.Fatalf("executable changed after failed verification: %q", contents)
	}
}

func TestApplySelfUpdateSkipsCurrentOrNewerVersion(t *testing.T) {
	originalVersion := version
	version = "0.6.8"
	t.Cleanup(func() { version = originalVersion })

	if err := applySelfUpdate(context.Background(), "0.6.8", "asset", "https://example.com/asset", "https://example.com/checksums.txt"); err != nil {
		t.Fatalf("current version update = %v, want nil", err)
	}
	if err := applySelfUpdate(context.Background(), "0.6.7", "asset", "https://example.com/asset", "https://example.com/checksums.txt"); err != nil {
		t.Fatalf("older version update = %v, want nil", err)
	}
}

func TestChecksumForUpdateAsset(t *testing.T) {
	const checksum = "5612e698e96c8b8ad15abc4c0a4f098eba9234354b4f248cb97f2528e215b094"
	got, err := checksumForUpdateAsset("SHA256 (speedtester) = "+checksum+"\n", "speedtester")
	if err != nil {
		t.Fatal(err)
	}
	if got != checksum {
		t.Fatalf("checksum = %q, want %q", got, checksum)
	}
}

func TestCompareSpeedtesterVersions(t *testing.T) {
	tests := []struct {
		current string
		target  string
		want    int
	}{
		{current: "0.6.7", target: "0.6.8", want: -1},
		{current: "v0.6.8", target: "0.6.8", want: 0},
		{current: "0.6.10", target: "0.6.9", want: 1},
	}
	for _, test := range tests {
		got, err := compareSpeedtesterVersions(test.current, test.target)
		if err != nil {
			t.Fatalf("compare %s to %s: %v", test.current, test.target, err)
		}
		if got != test.want {
			t.Fatalf("compare %s to %s = %d, want %d", test.current, test.target, got, test.want)
		}
	}
}

func TestValidateUpdateTargetRestrictsProductionUpdatesToGitHub(t *testing.T) {
	if err := validateUpdateTarget("relaydock-speedtester-linux-amd64", "https://example.com/relaydock-speedtester-linux-amd64", "https://example.com/checksums.txt"); err == nil {
		t.Fatal("non-GitHub production update source was accepted")
	}
	if err := validateUpdateRedirectURL("https://release-assets.githubusercontent.com/download"); err != nil {
		t.Fatalf("GitHub release redirect was rejected: %v", err)
	}
}
