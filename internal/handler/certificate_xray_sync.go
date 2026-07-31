package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path"
	"strings"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

const managedXrayCertDir = "/usr/local/etc/xray/certs"

func xrayCertMaterialHash(certPEM, keyPEM string) string {
	sum := sha256.Sum256([]byte(certPEM + "\x00" + keyPEM))
	return hex.EncodeToString(sum[:])
}

func xrayCertSyncKey(serverID, certID int64) string {
	return fmt.Sprintf("%d:%d", serverID, certID)
}

func (h *CertificateHandler) rememberXrayCertSync(serverID int64, cert *storage.Certificate) {
	if cert == nil || cert.ID <= 0 {
		return
	}
	h.xrayCertSynced.Store(xrayCertSyncKey(serverID, cert.ID), xrayCertMaterialHash(cert.CertPEM, cert.KeyPEM))
}

func (h *CertificateHandler) forgetXrayCertSync(serverID, certID int64) {
	h.xrayCertSynced.Delete(xrayCertSyncKey(serverID, certID))
}

func (h *CertificateHandler) needsXrayCertSync(serverID int64, cert *storage.Certificate) bool {
	if cert == nil || cert.ID <= 0 {
		return false
	}
	got, ok := h.xrayCertSynced.Load(xrayCertSyncKey(serverID, cert.ID))
	return !ok || got != xrayCertMaterialHash(cert.CertPEM, cert.KeyPEM)
}

func managedXrayCertPaths(domain string) (string, string) {
	name := certDeployFilename(domain)
	return path.Join(managedXrayCertDir, name+".pem"), path.Join(managedXrayCertDir, name+".key")
}

// collectManagedXrayCertPaths accepts only certificate/key pairs below the
// panel-managed directory. User-managed paths are deliberately not touched.
func collectManagedXrayCertPaths(configJSON string) map[string]string {
	refs := make(map[string]string)
	if strings.TrimSpace(configJSON) == "" {
		return refs
	}

	var root any
	if err := json.Unmarshal([]byte(configJSON), &root); err != nil {
		return refs
	}

	var walk func(any)
	walk = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			certPath, _ := node["certificateFile"].(string)
			keyPath, _ := node["keyFile"].(string)
			certPath = path.Clean(strings.TrimSpace(certPath))
			keyPath = path.Clean(strings.TrimSpace(keyPath))
			if strings.HasPrefix(certPath, managedXrayCertDir+"/") &&
				strings.HasPrefix(keyPath, managedXrayCertDir+"/") {
				refs[certPath] = keyPath
			}
			for _, child := range node {
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(root)
	return refs
}

func (h *CertificateHandler) managedXrayReferences(ctx context.Context, serverID int64) map[string]string {
	refs := make(map[string]string)
	merge := func(configJSON string) {
		for certPath, keyPath := range collectManagedXrayCertPaths(configJSON) {
			refs[certPath] = keyPath
		}
	}
	if current, err := h.repo.GetCurrentXraySnapshot(ctx, serverID); err == nil && current != nil {
		merge(current.ConfigJSON)
	}
	if pending, err := h.repo.GetPendingXrayRecovery(ctx, serverID); err == nil && pending != nil {
		merge(pending.ConfigJSON)
	}
	return refs
}

func certReferencedByManagedXrayPaths(cert *storage.Certificate, refs map[string]string) bool {
	if cert == nil {
		return false
	}
	certPath, keyPath := managedXrayCertPaths(cert.Domain)
	return refs[certPath] == keyPath
}

func (h *CertificateHandler) restartManagedXray(ctx context.Context, serverID int64, logPrefix string) error {
	if h.managedXrayRestart != nil {
		return h.managedXrayRestart(ctx, serverID, logPrefix)
	}
	if h.remoteManage == nil {
		return fmt.Errorf("remote manage handler not initialized")
	}
	return h.remoteManage.restartXrayWithRecovery(ctx, serverID, logPrefix)
}

func (h *CertificateHandler) restoreManagedXrayCert(ctx context.Context, server *storage.RemoteServer, previous *storage.Certificate) error {
	if previous == nil || previous.CertPEM == "" || previous.KeyPEM == "" {
		return fmt.Errorf("previous certificate material is unavailable")
	}
	if _, _, err := h.DeployCertToServerSync(ctx, server, previous); err != nil {
		return fmt.Errorf("restore previous certificate files: %w", err)
	}
	if err := h.restartManagedXray(ctx, server.ID, "CertificateRollback"); err != nil {
		h.forgetXrayCertSync(server.ID, previous.ID)
		return fmt.Errorf("restart Xray with previous certificate: %w", err)
	}
	return nil
}

func (h *CertificateHandler) deployManagedXrayCert(ctx context.Context, server *storage.RemoteServer, cert, previous *storage.Certificate) error {
	return h.repo.WithRemoteServerMutationLease(ctx, server.ID, func(leasedCtx context.Context) error {
		if _, _, err := h.DeployCertToServerSync(leasedCtx, server, cert); err != nil {
			h.forgetXrayCertSync(server.ID, cert.ID)
			if previous != nil && previous.CertPEM != "" && previous.KeyPEM != "" {
				rollbackErr := h.restoreManagedXrayCert(leasedCtx, server, previous)
				return errors.Join(fmt.Errorf("deploy renewed certificate: %w", err), rollbackErr)
			}
			return err
		}
		if err := h.restartManagedXray(leasedCtx, server.ID, "CertificateSync"); err != nil {
			h.forgetXrayCertSync(server.ID, cert.ID)
			if previous != nil && previous.CertPEM != "" && previous.KeyPEM != "" {
				rollbackErr := h.restoreManagedXrayCert(leasedCtx, server, previous)
				return errors.Join(fmt.Errorf("restart Xray with renewed certificate: %w", err), rollbackErr)
			}
			return err
		}
		return nil
	})
}

// syncManagedXrayAfterMaterialUpdate is called after a master-managed
// certificate is issued, renewed, or uploaded. It only updates agents whose
// current or pending Xray snapshot references the deterministic managed path.
func (h *CertificateHandler) syncManagedXrayAfterMaterialUpdate(cert *storage.Certificate, certPEM, keyPEM string) {
	if cert == nil || cert.ID <= 0 || cert.RemoteServerID != 0 || certPEM == "" || keyPEM == "" {
		return
	}
	updated := *cert
	updated.CertPEM = certPEM
	updated.KeyPEM = keyPEM
	updated.Status = storage.CertStatusValid
	lookupCtx, lookupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	servers, err := h.repo.ListRemoteServers(lookupCtx)
	lookupCancel()
	if err != nil {
		log.Printf("[Certificate] list remote servers for Xray certificate sync: %v", err)
		return
	}
	if len(servers) == 0 {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		h.xrayCertSyncMu.Lock()
		defer h.xrayCertSyncMu.Unlock()

		for i := range servers {
			refs := h.managedXrayReferences(ctx, servers[i].ID)
			if !certReferencedByManagedXrayPaths(&updated, refs) || !h.needsXrayCertSync(servers[i].ID, &updated) {
				continue
			}
			if err := h.deployManagedXrayCert(ctx, &servers[i], &updated, cert); err != nil {
				log.Printf("[Certificate] sync managed Xray certificate for %s on server %d: %v", updated.Domain, servers[i].ID, err)
				_ = h.repo.AppendCertificateLog(ctx, updated.ID, fmt.Sprintf("服务器 %s 的 Xray 证书同步失败，已尝试恢复旧证书: %v", servers[i].Name, err))
				continue
			}
			log.Printf("[Certificate] synced managed Xray certificate for %s on server %d", updated.Domain, servers[i].ID)
		}
	}()
}

// SyncManagedXrayCertificatesOnReconnect runs after the Agent configuration
// snapshot refresh. A successful unchanged deployment is skipped so ordinary
// reconnects cannot cause repeated Xray restarts.
func (h *CertificateHandler) SyncManagedXrayCertificatesOnReconnect(ctx context.Context, serverID int64) {
	h.xrayCertSyncMu.Lock()
	defer h.xrayCertSyncMu.Unlock()

	refs := h.managedXrayReferences(ctx, serverID)
	if len(refs) == 0 {
		return
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		log.Printf("[Certificate] get remote server for reconnect certificate sync: %v", err)
		return
	}
	certs, err := h.repo.ListValidCertificates(ctx)
	if err != nil {
		log.Printf("[Certificate] list certificates for reconnect certificate sync: %v", err)
		return
	}
	for i := range certs {
		cert := &certs[i]
		if cert.RemoteServerID != 0 || cert.CertPEM == "" || cert.KeyPEM == "" ||
			!certReferencedByManagedXrayPaths(cert, refs) || !h.needsXrayCertSync(serverID, cert) {
			continue
		}
		if err := h.deployManagedXrayCert(ctx, server, cert, nil); err != nil {
			log.Printf("[Certificate] reconnect sync for %s on server %d: %v", cert.Domain, serverID, err)
			continue
		}
		log.Printf("[Certificate] reconnect synced managed Xray certificate for %s on server %d", cert.Domain, serverID)
	}
}
