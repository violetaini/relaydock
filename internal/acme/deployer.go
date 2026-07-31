package acme

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

type certFileSnapshot struct {
	path   string
	data   []byte
	mode   fs.FileMode
	exists bool
}

type certFileDeployment struct {
	cert certFileSnapshot
	key  certFileSnapshot
}

func resolveCertTarget(path string) (string, error) {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil {
			return "", fmt.Errorf("resolve certificate symlink %s: %w", path, resolveErr)
		}
		return resolved, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect certificate target %s: %w", path, err)
	}
	return path, nil
}

func snapshotCertFile(path string, defaultMode fs.FileMode) (certFileSnapshot, error) {
	snapshot := certFileSnapshot{path: path, mode: defaultMode}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, fmt.Errorf("inspect existing file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return snapshot, fmt.Errorf("certificate target %s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot, fmt.Errorf("read existing file %s: %w", path, err)
	}
	snapshot.data = data
	snapshot.mode = info.Mode().Perm()
	snapshot.exists = true
	return snapshot, nil
}

func stageCertFile(path string, data []byte, mode fs.FileMode) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", fmt.Errorf("create directory for %s: %w", path, err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	tempPath := temp.Name()
	ok := false
	defer func() {
		_ = temp.Close()
		if !ok {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(mode); err != nil {
		return "", fmt.Errorf("set temporary file mode for %s: %w", path, err)
	}
	if _, err := temp.Write(data); err != nil {
		return "", fmt.Errorf("write temporary file for %s: %w", path, err)
	}
	if err := temp.Sync(); err != nil {
		return "", fmt.Errorf("sync temporary file for %s: %w", path, err)
	}
	if err := temp.Close(); err != nil {
		return "", fmt.Errorf("close temporary file for %s: %w", path, err)
	}
	ok = true
	return tempPath, nil
}

func syncCertDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func restoreCertFile(snapshot certFileSnapshot) error {
	if !snapshot.exists {
		if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove newly deployed file %s: %w", snapshot.path, err)
		}
		if err := syncCertDir(snapshot.path); err != nil {
			return fmt.Errorf("sync rollback directory for %s: %w", snapshot.path, err)
		}
		return nil
	}
	tempPath, err := stageCertFile(snapshot.path, snapshot.data, snapshot.mode)
	if err != nil {
		return err
	}
	defer os.Remove(tempPath)
	if err := os.Rename(tempPath, snapshot.path); err != nil {
		return fmt.Errorf("restore file %s: %w", snapshot.path, err)
	}
	if err := syncCertDir(snapshot.path); err != nil {
		return fmt.Errorf("sync restored file %s: %w", snapshot.path, err)
	}
	return nil
}

func (deployment *certFileDeployment) rollback() error {
	// Runtime reloads are serialized by the caller; restore both snapshots before
	// attempting the recovery reload.
	keyErr := restoreCertFile(deployment.key)
	certErr := restoreCertFile(deployment.cert)
	return errors.Join(keyErr, certErr)
}

func writeCertKeyFilesAtomic(certPEM, keyPEM []byte, certPath, keyPath string) (*certFileDeployment, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("deploy paths are required")
	}
	var err error
	certPath, err = resolveCertTarget(certPath)
	if err != nil {
		return nil, err
	}
	keyPath, err = resolveCertTarget(keyPath)
	if err != nil {
		return nil, err
	}
	certPath = filepath.Clean(certPath)
	keyPath = filepath.Clean(keyPath)
	if certPath == keyPath {
		return nil, fmt.Errorf("certificate and key paths must be different")
	}

	certSnapshot, err := snapshotCertFile(certPath, 0644)
	if err != nil {
		return nil, err
	}
	keySnapshot, err := snapshotCertFile(keyPath, 0600)
	if err != nil {
		return nil, err
	}
	deployment := &certFileDeployment{cert: certSnapshot, key: keySnapshot}

	certTemp, err := stageCertFile(certPath, certPEM, 0644)
	if err != nil {
		return nil, err
	}
	defer os.Remove(certTemp)
	keyTemp, err := stageCertFile(keyPath, keyPEM, 0600)
	if err != nil {
		return nil, err
	}
	defer os.Remove(keyTemp)

	if err := os.Rename(certTemp, certPath); err != nil {
		return nil, fmt.Errorf("install certificate %s: %w", certPath, err)
	}
	if err := os.Rename(keyTemp, keyPath); err != nil {
		rollbackErr := restoreCertFile(certSnapshot)
		return nil, errors.Join(fmt.Errorf("install private key %s: %w", keyPath, err), rollbackErr)
	}
	if err := syncCertDir(certPath); err != nil {
		rollbackErr := deployment.rollback()
		return nil, errors.Join(fmt.Errorf("sync certificate directory: %w", err), rollbackErr)
	}
	if filepath.Dir(certPath) != filepath.Dir(keyPath) {
		if err := syncCertDir(keyPath); err != nil {
			rollbackErr := deployment.rollback()
			return nil, errors.Join(fmt.Errorf("sync private key directory: %w", err), rollbackErr)
		}
	}
	return deployment, nil
}

// DeployCertFiles installs the certificate/key pair without reloading a service.
func DeployCertFiles(certPEM, keyPEM, certPath, keyPath string) error {
	_, err := writeCertKeyFilesAtomic([]byte(certPEM), []byte(keyPEM), certPath, keyPath)
	return err
}

// ReloadNginx sends nginx a reload signal.
func ReloadNginx() error {
	for _, nginxBin := range []string{"/usr/local/nginx/sbin/nginx", "nginx"} {
		if path, err := exec.LookPath(nginxBin); err == nil {
			cmd := exec.Command(path, "-s", "reload")
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("nginx reload: %s: %w", string(output), err)
			}
			return nil
		}
	}
	cmd := exec.Command("systemctl", "reload", "nginx")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx reload via systemctl: %s: %w", string(output), err)
	}
	return nil
}

// RestartXray restarts the xray service through systemd.
func RestartXray() error {
	cmd := exec.Command("systemctl", "restart", "xray")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("xray restart: %s: %w", string(output), err)
	}
	return nil
}

func reloadCertificateConsumers(reloadTarget string, reloadNginx, restartXray func() error) error {
	switch reloadTarget {
	case "", "none":
		return nil
	case "nginx":
		return reloadNginx()
	case "xray":
		return restartXray()
	case "both":
		if err := reloadNginx(); err != nil {
			return err
		}
		return restartXray()
	default:
		return fmt.Errorf("unsupported reload target %q", reloadTarget)
	}
}

func deployWithReloaders(certPEM, keyPEM, certPath, keyPath, reloadTarget string, reloadNginx, restartXray func() error) error {
	switch reloadTarget {
	case "", "none", "nginx", "xray", "both":
	default:
		return fmt.Errorf("unsupported reload target %q", reloadTarget)
	}
	deployment, err := writeCertKeyFilesAtomic([]byte(certPEM), []byte(keyPEM), certPath, keyPath)
	if err != nil {
		return err
	}
	if reloadNginx == nil {
		reloadNginx = ReloadNginx
	}
	if restartXray == nil {
		restartXray = RestartXray
	}
	if err := reloadCertificateConsumers(reloadTarget, reloadNginx, restartXray); err != nil {
		rollbackErr := deployment.rollback()
		var recoveryErr error
		if rollbackErr == nil {
			recoveryErr = reloadCertificateConsumers(reloadTarget, reloadNginx, restartXray)
		}
		return errors.Join(
			fmt.Errorf("reload certificate consumers: %w", err),
			wrapCertRollbackError(rollbackErr),
			wrapCertRecoveryReloadError(recoveryErr),
		)
	}
	return nil
}

func wrapCertRollbackError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("restore previous certificate files: %w", err)
}

func wrapCertRecoveryReloadError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("reload services after certificate rollback: %w", err)
}

// DeployWithXrayRestarter lets callers serialize the Xray restart with other
// runtime/config mutations. A nil callback preserves the standalone behavior.
func DeployWithXrayRestarter(certPEM, keyPEM, certPath, keyPath, reloadTarget string, restartXray func() error) error {
	return deployWithReloaders(certPEM, keyPEM, certPath, keyPath, reloadTarget, ReloadNginx, restartXray)
}

// Deploy installs a certificate pair and reloads the selected consumers.
func Deploy(certPEM, keyPEM, certPath, keyPath, reloadTarget string) error {
	return DeployWithXrayRestarter(certPEM, keyPEM, certPath, keyPath, reloadTarget, nil)
}
