// Package productrelease defines the immutable product-release contract used
// by the control-plane updater. A product release can change the web bundle
// independently of the control-plane binary, but every component remains
// bound to one signed GitHub Release manifest.
package productrelease

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const SchemaVersion = 1

const (
	ComponentControlPlane = "control_plane"
	ComponentWeb          = "web"
	ComponentGuard        = "guard_assets"
	ComponentSpeedtester  = "speedtester_assets"
)

var (
	releaseIDPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	assetNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	sha256Pattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// Asset records a release asset as declared by the product manifest. The
// updater also validates the GitHub-provided asset digest before using it.
type Asset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Component records the version and API contract for one independently
// installable product component. Changed=false permits a frontend-only
// product release without forcing a no-op control-plane replacement.
type Component struct {
	Version     string  `json:"version"`
	APIContract int     `json:"api_contract"`
	Changed     bool    `json:"changed"`
	Assets      []Asset `json:"assets,omitempty"`
}

// Manifest is the release-wide source of truth. Components are keyed using
// the Component* constants so a future schema can add components without
// changing the transport shape.
type Manifest struct {
	Schema     int                  `json:"schema"`
	ReleaseID  string               `json:"release_id"`
	Components map[string]Component `json:"components"`
}

// Parse validates an untrusted manifest before it is used to choose assets.
func Parse(raw []byte) (Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse release manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate enforces the compact schema shared by release assembly, the panel,
// and the updater helper.
func (m Manifest) Validate() error {
	if m.Schema != SchemaVersion {
		return fmt.Errorf("unsupported release manifest schema: %d", m.Schema)
	}
	if !releaseIDPattern.MatchString(m.ReleaseID) {
		return fmt.Errorf("invalid release id: %q", m.ReleaseID)
	}
	if len(m.Components) == 0 {
		return errors.New("release manifest has no components")
	}
	for _, required := range []string{ComponentControlPlane, ComponentWeb} {
		if _, ok := m.Components[required]; !ok {
			return fmt.Errorf("release manifest is missing %s", required)
		}
	}
	for name, component := range m.Components {
		if !assetNamePattern.MatchString(name) {
			return fmt.Errorf("invalid component name: %q", name)
		}
		if strings.TrimSpace(component.Version) == "" {
			return fmt.Errorf("component %s has no version", name)
		}
		if component.APIContract < 1 {
			return fmt.Errorf("component %s has invalid API contract", name)
		}
		if component.Changed && len(component.Assets) == 0 {
			return fmt.Errorf("changed component %s has no assets", name)
		}
		seenAssets := make(map[string]struct{}, len(component.Assets))
		for _, asset := range component.Assets {
			if !assetNamePattern.MatchString(asset.Name) {
				return fmt.Errorf("component %s has invalid asset name: %q", name, asset.Name)
			}
			if _, exists := seenAssets[asset.Name]; exists {
				return fmt.Errorf("component %s repeats asset %s", name, asset.Name)
			}
			seenAssets[asset.Name] = struct{}{}
			if !sha256Pattern.MatchString(strings.ToLower(asset.SHA256)) {
				return fmt.Errorf("component %s asset %s has invalid SHA-256", name, asset.Name)
			}
			if asset.Size <= 0 {
				return fmt.Errorf("component %s asset %s has invalid size", name, asset.Name)
			}
		}
	}
	web := m.Components[ComponentWeb]
	if web.Changed && len(web.Assets) != 1 {
		return errors.New("changed web component must contain exactly one archive")
	}
	return nil
}

// Component returns a component by name. A copy is returned so callers cannot
// mutate the manifest stored by an update transaction.
func (m Manifest) Component(name string) (Component, bool) {
	component, ok := m.Components[name]
	return component, ok
}

// AssetNames returns deterministic asset ordering for UI and verification.
func (m Manifest) AssetNames() []string {
	var names []string
	for _, component := range m.Components {
		for _, asset := range component.Assets {
			names = append(names, asset.Name)
		}
	}
	sort.Strings(names)
	return names
}
