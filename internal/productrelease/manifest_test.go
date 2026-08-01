package productrelease

import (
	"encoding/json"
	"strings"
	"testing"
)

func validManifest() Manifest {
	return Manifest{
		Schema:    SchemaVersion,
		ReleaseID: "v1.2.3",
		Components: map[string]Component{
			ComponentControlPlane: {Version: "1.2.3", APIContract: 1, Changed: true, Assets: []Asset{{Name: "arcway-linux-amd64", SHA256: strings.Repeat("a", 64), Size: 1}}},
			ComponentWeb:          {Version: "v1.2.3", APIContract: 1, Changed: true, Assets: []Asset{{Name: "relaydock-web-v1.2.3.tar.gz", SHA256: strings.Repeat("b", 64), Size: 1}}},
		},
	}
}

func TestManifestRoundTrip(t *testing.T) {
	want := validManifest()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReleaseID != want.ReleaseID || len(got.AssetNames()) != 2 {
		t.Fatalf("manifest = %+v", got)
	}
}

func TestManifestRejectsUnsafeWebComponent(t *testing.T) {
	manifest := validManifest()
	web := manifest.Components[ComponentWeb]
	web.Assets = append(web.Assets, web.Assets[0])
	manifest.Components[ComponentWeb] = web
	if err := manifest.Validate(); err == nil {
		t.Fatal("invalid web assets accepted")
	}
}
