package handler

import (
	"testing"

	"github.com/violetaini/relaydock/internal/version"
)

func TestSpeedtesterUpdateMessageOnlyTargetsCompatibleOlderClients(t *testing.T) {
	update, available := speedtesterUpdateMessage(
		"0.6.7",
		[]string{"speedtest", speedtesterSelfUpdateCapability},
		"linux",
		"amd64",
	)
	if !available {
		t.Fatal("expected an update for compatible older tester")
	}
	if update.Type != "update" || update.Version != version.Version {
		t.Fatalf("update = %#v", update)
	}
	if update.AssetName != "relaydock-speedtester-linux-amd64" || update.DownloadURL == "" || update.ChecksumsURL == "" {
		t.Fatalf("update does not provide an immutable verified asset: %#v", update)
	}

	for _, testCase := range []struct {
		name    string
		version string
		caps    []string
		goos    string
		goarch  string
	}{
		{name: "legacy client has no update capability", version: "0.6.7", caps: []string{"speedtest"}, goos: "linux", goarch: "amd64"},
		{name: "already current", version: version.Version, caps: []string{speedtesterSelfUpdateCapability}, goos: "linux", goarch: "amd64"},
		{name: "newer client", version: "999.0.0", caps: []string{speedtesterSelfUpdateCapability}, goos: "linux", goarch: "amd64"},
		{name: "unsupported platform", version: "0.6.7", caps: []string{speedtesterSelfUpdateCapability}, goos: "darwin", goarch: "arm64"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if update, available := speedtesterUpdateMessage(testCase.version, testCase.caps, testCase.goos, testCase.goarch); available {
				t.Fatalf("unexpected update: %#v", update)
			}
		})
	}
}
