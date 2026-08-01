package productrelease

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const StateFilename = "installed-release.json"

// InstalledComponent is the locally activated state for a component. It is
// intentionally separate from the release manifest: an operator may update a
// compatible web-only release without replacing the control-plane binary.
type InstalledComponent struct {
	Version     string `json:"version"`
	APIContract int    `json:"api_contract"`
}

// InstalledState is persisted only after every required component has passed
// its activation checks. The updater reads it to identify frontend-only work.
type InstalledState struct {
	Schema     int                           `json:"schema"`
	ReleaseID  string                        `json:"release_id"`
	UpdatedAt  time.Time                     `json:"updated_at"`
	Components map[string]InstalledComponent `json:"components"`
}

func NewInstalledState(releaseID string, components map[string]Component) InstalledState {
	installed := InstalledState{
		Schema:     SchemaVersion,
		ReleaseID:  releaseID,
		UpdatedAt:  time.Now().UTC(),
		Components: make(map[string]InstalledComponent, len(components)),
	}
	for name, component := range components {
		installed.Components[name] = InstalledComponent{
			Version:     component.Version,
			APIContract: component.APIContract,
		}
	}
	return installed
}

func (s InstalledState) Validate() error {
	if s.Schema != SchemaVersion {
		return fmt.Errorf("unsupported installed release schema: %d", s.Schema)
	}
	if !releaseIDPattern.MatchString(s.ReleaseID) {
		return fmt.Errorf("invalid installed release id: %q", s.ReleaseID)
	}
	if len(s.Components) == 0 {
		return errors.New("installed release has no components")
	}
	for name, component := range s.Components {
		if !assetNamePattern.MatchString(name) || strings.TrimSpace(component.Version) == "" || component.APIContract < 1 {
			return fmt.Errorf("invalid installed component %q", name)
		}
	}
	return nil
}

func StatePath(stateDir string) string {
	return filepath.Join(stateDir, StateFilename)
}

func LoadInstalledState(stateDir string) (InstalledState, error) {
	path := StatePath(stateDir)
	raw, err := os.ReadFile(path)
	if err != nil {
		return InstalledState{}, err
	}
	var state InstalledState
	if err := json.Unmarshal(raw, &state); err != nil {
		return InstalledState{}, fmt.Errorf("parse installed release state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return InstalledState{}, err
	}
	return state, nil
}

// WriteInstalledState publishes a completed state atomically. The state
// directory is private to the service so a local unprivileged user cannot
// manufacture a false compatibility record.
func WriteInstalledState(stateDir string, state InstalledState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create update state directory: %w", err)
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	path := StatePath(stateDir)
	temp, err := os.CreateTemp(stateDir, ".installed-release-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0600); err != nil {
		return err
	}
	if _, err := temp.Write(encoded); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	committed = true
	if err := syncWebDirectory(stateDir); err != nil {
		return fmt.Errorf("sync installed release state directory: %w", err)
	}
	return nil
}

// IsNotExist treats a missing state record as an unmanaged legacy deployment.
func IsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
