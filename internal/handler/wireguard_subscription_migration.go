package handler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

type wireGuardSubscriptionFileMigration struct {
	path      string
	content   string
	protected string
}

// ProtectPersistedWireGuardSubscriptionSecrets upgrades legacy subscription
// files and rule history before the HTTP server starts. The preflight phase
// validates every payload first, so an invalid file stops startup without
// exposing a mixture of plaintext and encrypted subscription responses.
func ProtectPersistedWireGuardSubscriptionSecrets(ctx context.Context, repo *storage.TrafficRepository, baseDir string) error {
	if repo == nil {
		return errors.New("WireGuard 订阅私钥存储不可用")
	}
	baseDir = filepath.Clean(strings.TrimSpace(baseDir))
	if baseDir == "." || baseDir == "" {
		return errors.New("订阅目录不能为空")
	}
	unlock, err := lockSubscriptionStore()
	if err != nil {
		return err
	}
	defer unlock()
	if err := os.Chmod(baseDir, 0700); err != nil {
		return fmt.Errorf("收紧订阅目录权限失败: %w", err)
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return fmt.Errorf("读取订阅目录失败: %w", err)
	}
	files := make([]wireGuardSubscriptionFileMigration, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !isYAMLFile(entry.Name()) {
			continue
		}
		path := filepath.Join(baseDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("读取订阅 %s 失败: %w", entry.Name(), err)
		}
		protected, err := protectWireGuardSubscriptionContent(ctx, repo, entry.Name(), string(content), true)
		if err != nil {
			return fmt.Errorf("迁移订阅 %s 的 WireGuard 私钥失败: %w", entry.Name(), err)
		}
		files = append(files, wireGuardSubscriptionFileMigration{
			path:      path,
			content:   string(content),
			protected: protected,
		})
	}

	versions, err := repo.ListAllRuleVersionContents(ctx)
	if err != nil {
		return fmt.Errorf("读取订阅历史失败: %w", err)
	}
	versionUpdates := make(map[int64]string)
	for _, version := range versions {
		protected, err := protectWireGuardSubscriptionContent(ctx, repo, version.Filename, version.Content, true)
		if err != nil {
			return fmt.Errorf("迁移订阅 %s 的历史版本 %d 失败: %w", version.Filename, version.ID, err)
		}
		if protected != version.Content {
			versionUpdates[version.ID] = protected
		}
	}

	// The storage method applies all history changes in one transaction and
	// compacts SQLite afterwards so removed plaintext is not left in WAL/free
	// pages. A later file-write failure keeps the service offline; retrying this
	// migration is idempotent.
	if err := repo.UpdateRuleVersionContents(ctx, versionUpdates); err != nil {
		return fmt.Errorf("写入加密订阅历史失败: %w", err)
	}
	for _, file := range files {
		if file.protected != file.content {
			if err := writePrivateSubscriptionFileUnlocked(file.path, []byte(file.protected)); err != nil {
				return fmt.Errorf("写入加密订阅 %s 失败: %w", filepath.Base(file.path), err)
			}
			continue
		}
		if err := os.Chmod(file.path, 0600); err != nil {
			return fmt.Errorf("收紧订阅 %s 权限失败: %w", filepath.Base(file.path), err)
		}
	}
	return nil
}
