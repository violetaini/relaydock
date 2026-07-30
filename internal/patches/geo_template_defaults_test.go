package patches

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

const legacyTemplateYAML = `mode: rule
dns:
  enable: true
rules:
  - MATCH,DIRECT
`

func TestApplyGEODefaultsAddsBuiltInTemplatesAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	for _, name := range geoDefaultTemplateNames {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(legacyTemplateYAML), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	customPath := filepath.Join(dir, "custom.yaml")
	customBefore := []byte("mode: direct\n")
	if err := os.WriteFile(customPath, customBefore, 0o600); err != nil {
		t.Fatalf("write custom template: %v", err)
	}

	patched, err := ApplyGEODefaults(dir)
	if err != nil {
		t.Fatalf("ApplyGEODefaults: %v", err)
	}
	if patched != len(geoDefaultTemplateNames) {
		t.Fatalf("patched = %d, want %d", patched, len(geoDefaultTemplateNames))
	}

	afterFirstRun := make(map[string][]byte, len(geoDefaultTemplateNames))
	for _, name := range geoDefaultTemplateNames {
		path := filepath.Join(dir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		afterFirstRun[name] = content
		assertGEODefaults(t, name, content)

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, got)
		}
	}

	patched, err = ApplyGEODefaults(dir)
	if err != nil {
		t.Fatalf("second ApplyGEODefaults: %v", err)
	}
	if patched != 0 {
		t.Fatalf("second patched = %d, want 0", patched)
	}
	for _, name := range geoDefaultTemplateNames {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s after second run: %v", name, err)
		}
		if !reflect.DeepEqual(content, afterFirstRun[name]) {
			t.Errorf("%s changed on the idempotent second run", name)
		}
	}

	customAfter, err := os.ReadFile(customPath)
	if err != nil {
		t.Fatalf("read custom template: %v", err)
	}
	if !reflect.DeepEqual(customAfter, customBefore) {
		t.Errorf("non-built-in template changed: got %q, want %q", customAfter, customBefore)
	}
}

func TestApplyGEODefaultsRespectsAnyExplicitTopLevelGEOSetting(t *testing.T) {
	tests := map[string]string{
		"geodata mode false":   "geodata-mode: false\n",
		"auto update false":    "geo-auto-update: false\n",
		"custom interval":      "geo-update-interval: 168\n",
		"custom download URLs": "geox-url:\n  geoip: https://example.com/custom-geoip.dat\n",
	}

	for name, explicitSetting := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, geoDefaultTemplateNames[0])
			before := []byte("# user-managed GEO setting\nmode: rule\n" + explicitSetting + "rules: []\n")
			if err := os.WriteFile(path, before, 0o640); err != nil {
				t.Fatalf("write template: %v", err)
			}

			patched, err := ApplyGEODefaults(dir)
			if err != nil {
				t.Fatalf("ApplyGEODefaults: %v", err)
			}
			if patched != 0 {
				t.Fatalf("patched = %d, want 0", patched)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read template: %v", err)
			}
			if !reflect.DeepEqual(after, before) {
				t.Errorf("explicit GEO configuration was changed: got %q, want %q", after, before)
			}
		})
	}
}

func TestApplyGEODefaultsDoesNotOverwriteInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, geoDefaultTemplateNames[0])
	before := []byte("mode: [unterminated\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	patched, err := ApplyGEODefaults(dir)
	if err == nil {
		t.Fatal("ApplyGEODefaults error = nil, want YAML parse error")
	}
	if patched != 0 {
		t.Fatalf("patched = %d, want 0", patched)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read template: %v", readErr)
	}
	if !reflect.DeepEqual(after, before) {
		t.Errorf("invalid YAML was overwritten: got %q, want %q", after, before)
	}
}

func assertGEODefaults(t *testing.T, name string, content []byte) {
	t.Helper()
	var config map[string]any
	if err := yaml.Unmarshal(content, &config); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}

	wantScalars := map[string]any{
		"geodata-mode":        true,
		"geo-auto-update":     true,
		"geo-update-interval": 24,
	}
	for key, want := range wantScalars {
		if got := config[key]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s %s = %#v, want %#v", name, key, got, want)
		}
	}

	gotURLs, ok := config["geox-url"].(map[string]any)
	if !ok {
		t.Fatalf("%s geox-url = %#v, want mapping", name, config["geox-url"])
	}
	wantURLs := map[string]any{
		"geoip":   "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
		"geosite": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
		"mmdb":    "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
		"asn":     "https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb",
	}
	if !reflect.DeepEqual(gotURLs, wantURLs) {
		t.Errorf("%s geox-url = %#v, want %#v", name, gotURLs, wantURLs)
	}
}
