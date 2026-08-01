package productrelease

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeWebArchive(t *testing.T, path string, metadata WebMetadata, extra func(*tar.Writer)) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	writer := tar.NewWriter(gzipWriter)
	write := func(name, content string) {
		t.Helper()
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", `<html><body>__RELAYDOCK_DEFAULT_THEME__<script src="/assets/app-12345678.js"></script></body></html>`)
	write("assets/app-12345678.js", "console.log('ok')")
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	write(WebMetadataFilename, string(raw))
	if extra != nil {
		extra(writer)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func createManagedWebRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	current := filepath.Join(root, "releases", "v1.0.0")
	if err := os.MkdirAll(filepath.Join(current, "assets"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, "index.html"), []byte(`__RELAYDOCK_DEFAULT_THEME__<script src="/assets/old-12345678.js"></script>`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, "assets", "old-12345678.js"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(WebMetadata{Schema: SchemaVersion, ReleaseID: "v1.0.0", APIContract: 1})
	if err := os.WriteFile(filepath.Join(current, WebMetadataFilename), metadata, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/v1.0.0", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestStageAndActivateWebArchive(t *testing.T) {
	root := createManagedWebRoot(t)
	archive := filepath.Join(t.TempDir(), "web.tar.gz")
	metadata := WebMetadata{Schema: SchemaVersion, ReleaseID: "v1.0.1", APIContract: 1}
	writeWebArchive(t, archive, metadata, nil)
	stage, err := StageWebArchive(archive, root, "v1.0.1", metadata)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := ActivateStagedWebRelease(root, stage, "v1.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, release, err := managedCurrentTarget(root); err != nil || release != "v1.0.1" {
		t.Fatalf("current = %q, %v", release, err)
	}
	if _, err := os.Stat(filepath.Join(root, "releases", "v1.0.1", "assets", "old-12345678.js")); err != nil {
		t.Fatalf("old hashed asset was not carried forward: %v", err)
	}
	if err := RollbackWebActivation(root, activation); err != nil {
		t.Fatal(err)
	}
	if _, release, err := managedCurrentTarget(root); err != nil || release != "v1.0.0" {
		t.Fatalf("rolled back current = %q, %v", release, err)
	}
}

func TestManagedWebRootAcceptsCanonicalAbsoluteCurrentLink(t *testing.T) {
	root := createManagedWebRoot(t)
	currentLink := filepath.Join(root, "current")
	if err := os.Remove(currentLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "releases", "v1.0.0"), currentLink); err != nil {
		t.Fatal(err)
	}

	if managed, err := ManagedWebRoot(currentLink); err != nil || managed != root {
		t.Fatalf("managed root = %q, %v", managed, err)
	}
	if release, err := CurrentManagedWebRelease(currentLink); err != nil || release != "v1.0.0" {
		t.Fatalf("absolute current release = %q, %v", release, err)
	}

	archive := filepath.Join(t.TempDir(), "web.tar.gz")
	metadata := WebMetadata{Schema: SchemaVersion, ReleaseID: "v1.0.1", APIContract: 1}
	writeWebArchive(t, archive, metadata, nil)
	stage, err := StageWebArchive(archive, root, metadata.ReleaseID, metadata)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := PrepareWebActivation(root, stage, metadata.ReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if activation.CurrentTarget != "releases/v1.0.0" {
		t.Fatalf("normalized current target = %q", activation.CurrentTarget)
	}
	if err := ActivatePreparedWebRelease(root, activation); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(currentLink); err != nil || target != "releases/v1.0.1" {
		t.Fatalf("new current link = %q, %v", target, err)
	}
}

func TestPreparedWebActivationIsResumableAndRetryable(t *testing.T) {
	root := createManagedWebRoot(t)
	archive := filepath.Join(t.TempDir(), "web.tar.gz")
	metadata := WebMetadata{Schema: SchemaVersion, ReleaseID: "v1.0.1", APIContract: 1}
	writeWebArchive(t, archive, metadata, nil)

	stage, err := StageWebArchive(archive, root, metadata.ReleaseID, metadata)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := PrepareWebActivation(root, stage, metadata.ReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if err := ActivatePreparedWebRelease(root, activation); err != nil {
		t.Fatal(err)
	}
	// A helper restart after the current link was replaced must be harmless.
	if err := ActivatePreparedWebRelease(root, activation); err != nil {
		t.Fatalf("resuming published activation: %v", err)
	}
	if err := RollbackWebActivation(root, activation); err != nil {
		t.Fatal(err)
	}

	// Rollback retains the published release for inspection. A retry must use a
	// fresh verified directory rather than accidentally re-serving that copy.
	stage, err = StageWebArchive(archive, root, metadata.ReleaseID, metadata)
	if err != nil {
		t.Fatalf("stage retry: %v", err)
	}
	activation, err = PrepareWebActivation(root, stage, metadata.ReleaseID)
	if err != nil {
		t.Fatalf("prepare retry: %v", err)
	}
	if err := ActivatePreparedWebRelease(root, activation); err != nil {
		t.Fatalf("activate retry: %v", err)
	}
	if _, release, err := managedCurrentTarget(root); err != nil || release != metadata.ReleaseID {
		t.Fatalf("retry current release = %q, %v", release, err)
	}
}

func TestRollbackWebActivationRejectsMissingRecordedRelease(t *testing.T) {
	root := createManagedWebRoot(t)
	archive := filepath.Join(t.TempDir(), "web.tar.gz")
	metadata := WebMetadata{Schema: SchemaVersion, ReleaseID: "v1.0.1", APIContract: 1}
	writeWebArchive(t, archive, metadata, nil)
	stage, err := StageWebArchive(archive, root, metadata.ReleaseID, metadata)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := PrepareWebActivation(root, stage, metadata.ReleaseID)
	if err != nil {
		t.Fatal(err)
	}
	if err := ActivatePreparedWebRelease(root, activation); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "releases", "v1.0.0")); err != nil {
		t.Fatal(err)
	}
	if err := RollbackWebActivation(root, activation); err == nil {
		t.Fatal("rollback accepted a missing recorded release")
	}
	if target, err := os.Readlink(filepath.Join(root, "current")); err != nil || target != "releases/v1.0.1" {
		t.Fatalf("rollback changed current link after validation failure: %q, %v", target, err)
	}
}

func TestStageWebArchiveRejectsTraversal(t *testing.T) {
	root := createManagedWebRoot(t)
	archive := filepath.Join(t.TempDir(), "bad.tar.gz")
	metadata := WebMetadata{Schema: SchemaVersion, ReleaseID: "v1.0.1", APIContract: 1}
	writeWebArchive(t, archive, metadata, func(writer *tar.Writer) {
		if err := writer.WriteHeader(&tar.Header{Name: "../escape", Mode: 0644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := StageWebArchive(archive, root, "v1.0.1", metadata); err == nil {
		t.Fatal("traversal archive was accepted")
	}
}
