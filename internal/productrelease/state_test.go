package productrelease

import "testing"

func TestWriteAndLoadInstalledState(t *testing.T) {
	directory := t.TempDir()
	state := NewInstalledState("v1.2.3", validManifest().Components)
	if err := WriteInstalledState(directory, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadInstalledState(directory)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ReleaseID != state.ReleaseID || loaded.Components[ComponentWeb].Version != "v1.2.3" {
		t.Fatalf("loaded state = %+v", loaded)
	}
}
