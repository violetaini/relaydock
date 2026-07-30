package patches

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var geoDefaultTemplateNames = []string{
	"fake_ip__v3.yaml",
	"redirhost__v3.yaml",
}

var geoTopLevelKeys = map[string]struct{}{
	"geodata-mode":        {},
	"geo-auto-update":     {},
	"geo-update-interval": {},
	"geox-url":            {},
}

const geoDefaultsYAML = `
geodata-mode: true
geo-auto-update: true
geo-update-interval: 24
geox-url:
  geoip: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat
  geosite: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat
  mmdb: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb
  asn: https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb
`

// ApplyGEODefaults adds the current GEO defaults to the two built-in V3 templates.
// Any explicit top-level GEO setting marks the whole file as user-managed, so it
// is left byte-for-byte unchanged.
func ApplyGEODefaults(dir string) (int, error) {
	if dir == "" {
		dir = "rule_templates"
	}

	patched := 0
	var patchErrors []error
	for _, name := range geoDefaultTemplateNames {
		applied, err := applyGEODefaultsToFile(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			patchErrors = append(patchErrors, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if applied {
			patched++
		}
	}

	return patched, errors.Join(patchErrors...)
}

func applyGEODefaultsToFile(path string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("stat: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil {
		return false, fmt.Errorf("parse: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return false, nil
	}
	rootMap := root.Content[0]
	if rootMap.Kind != yaml.MappingNode {
		return false, nil
	}

	for i := 0; i+1 < len(rootMap.Content); i += 2 {
		if _, explicit := geoTopLevelKeys[rootMap.Content[i].Value]; explicit {
			return false, nil
		}
	}

	var defaults yaml.Node
	if err := yaml.Unmarshal([]byte(geoDefaultsYAML), &defaults); err != nil {
		return false, fmt.Errorf("parse defaults: %w", err)
	}
	if defaults.Kind != yaml.DocumentNode || len(defaults.Content) == 0 || defaults.Content[0].Kind != yaml.MappingNode {
		return false, errors.New("parse defaults: expected mapping document")
	}
	rootMap.Content = append(rootMap.Content, defaults.Content[0].Content...)

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&root); err != nil {
		return false, fmt.Errorf("marshal: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return false, fmt.Errorf("close encoder: %w", err)
	}

	if err := writeGEOFileAtomically(path, unescapeUnicodeEmoji(buf.Bytes()), info.Mode().Perm()); err != nil {
		return false, err
	}
	return true, nil
}

func writeGEOFileAtomically(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".geo-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp: %w", err)
	}
	return nil
}
