package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"miaomiaowux/internal/storage"

	"gopkg.in/yaml.v3"
)

const wireGuardNodeSecretReferencePrefix = "arcway-node-secret:v1:"

var errPersistedWireGuardPrivateKey = errors.New("配置包含未关联到面板节点的 WireGuard 客户端私钥；请先在节点管理中创建该节点")
var errUntrustedWireGuardSecretReference = errors.New("配置包含无效的 WireGuard 节点私钥引用")

// protectWireGuardSubscriptionContent replaces managed WireGuard private keys
// with non-secret node references before the YAML is persisted. References
// supplied by callers are rejected so a user cannot guess another node ID and
// use the subscription endpoint as a secret decryption oracle.
func protectWireGuardSubscriptionContent(ctx context.Context, repo *storage.TrafficRepository, content string) (string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return "", err
	}

	privateKeys := collectLiteralWireGuardPrivateKeys(&root)
	if len(privateKeys) == 0 {
		if containsWireGuardNodeSecretReference(&root) {
			return "", errUntrustedWireGuardSecretReference
		}
		return content, nil
	}
	if repo == nil {
		return "", errPersistedWireGuardPrivateKey
	}

	nodes, err := repo.ListAllNodes(ctx)
	if err != nil {
		return "", fmt.Errorf("读取 WireGuard 节点密钥失败: %w", err)
	}
	matches := make(map[string]int64, len(privateKeys))
	for _, node := range nodes {
		if strings.ToLower(strings.TrimSpace(node.Protocol)) != "wireguard" {
			continue
		}
		privateKey := wireGuardPrivateKeyFromNodeConfig(node.ClashConfig)
		if privateKey == "" {
			continue
		}
		for _, candidate := range privateKeys {
			if equalManagedWireGuardKeys(privateKey, candidate) {
				if existing, ok := matches[candidate]; !ok || node.ID < existing {
					matches[candidate] = node.ID
				}
			}
		}
	}
	for _, privateKey := range privateKeys {
		if matches[privateKey] <= 0 {
			return "", errPersistedWireGuardPrivateKey
		}
	}

	changed, err := rewriteWireGuardPrivateKeys(&root, func(value string) (string, error) {
		if strings.HasPrefix(strings.TrimSpace(value), wireGuardNodeSecretReferencePrefix) {
			return "", errUntrustedWireGuardSecretReference
		}
		nodeID := matches[strings.TrimSpace(value)]
		if nodeID <= 0 {
			return "", errPersistedWireGuardPrivateKey
		}
		return wireGuardNodeSecretReferencePrefix + strconv.FormatInt(nodeID, 10), nil
	})
	if err != nil {
		return "", err
	}
	if !changed {
		return content, nil
	}
	protected, err := MarshalYAMLWithIndent(&root)
	if err != nil {
		return "", err
	}
	return string(protected), nil
}

// hydrateWireGuardSubscriptionContent resolves trusted references only in
// memory immediately before an authorized editor or subscription response.
func hydrateWireGuardSubscriptionContent(ctx context.Context, repo *storage.TrafficRepository, content string) (string, error) {
	if !strings.Contains(content, wireGuardNodeSecretReferencePrefix) {
		return content, nil
	}
	if repo == nil {
		return "", errors.New("WireGuard 节点私钥存储不可用")
	}

	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return "", err
	}
	cache := make(map[int64]string)
	changed, err := rewriteWireGuardPrivateKeys(&root, func(value string) (string, error) {
		nodeID, ok := parseWireGuardNodeSecretReference(value)
		if !ok {
			if strings.HasPrefix(strings.TrimSpace(value), wireGuardNodeSecretReferencePrefix) {
				return "", errUntrustedWireGuardSecretReference
			}
			return value, nil
		}
		if privateKey, ok := cache[nodeID]; ok {
			return privateKey, nil
		}
		node, err := repo.GetNodeByID(ctx, nodeID)
		if err != nil {
			return "", fmt.Errorf("读取 WireGuard 节点 %d 私钥失败: %w", nodeID, err)
		}
		if strings.ToLower(strings.TrimSpace(node.Protocol)) != "wireguard" {
			return "", fmt.Errorf("节点 %d 不是 WireGuard 节点", nodeID)
		}
		privateKey := wireGuardPrivateKeyFromNodeConfig(node.ClashConfig)
		if privateKey == "" {
			return "", fmt.Errorf("WireGuard 节点 %d 私钥不可用", nodeID)
		}
		cache[nodeID] = privateKey
		return privateKey, nil
	})
	if err != nil {
		return "", err
	}
	if !changed {
		return content, nil
	}
	hydrated, err := MarshalYAMLWithIndent(&root)
	if err != nil {
		return "", err
	}
	return string(hydrated), nil
}

func collectLiteralWireGuardPrivateKeys(root *yaml.Node) []string {
	seen := make(map[string]struct{})
	var values []string
	_, _ = rewriteWireGuardPrivateKeys(root, func(value string) (string, error) {
		value = strings.TrimSpace(value)
		if value == "" || strings.HasPrefix(value, wireGuardNodeSecretReferencePrefix) {
			return value, nil
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			values = append(values, value)
		}
		return value, nil
	})
	return values
}

func containsWireGuardNodeSecretReference(root *yaml.Node) bool {
	found := false
	_, _ = rewriteWireGuardPrivateKeys(root, func(value string) (string, error) {
		if strings.HasPrefix(strings.TrimSpace(value), wireGuardNodeSecretReferencePrefix) {
			found = true
		}
		return value, nil
	})
	return found
}

func rewriteWireGuardPrivateKeys(node *yaml.Node, rewrite func(string) (string, error)) (bool, error) {
	if node == nil {
		return false, nil
	}
	changed := false
	if node.Kind == yaml.MappingNode {
		protocol := ""
		var privateKeyValue *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			switch normalizeWireGuardYAMLKey(key.Value) {
			case "type":
				protocol = strings.ToLower(strings.TrimSpace(value.Value))
			case "privatekey":
				privateKeyValue = value
			}
		}
		if (protocol == "wireguard" || protocol == "wg") && privateKeyValue != nil && strings.TrimSpace(privateKeyValue.Value) != "" {
			replacement, err := rewrite(privateKeyValue.Value)
			if err != nil {
				return false, err
			}
			if replacement != privateKeyValue.Value {
				privateKeyValue.Value = replacement
				privateKeyValue.Tag = "!!str"
				privateKeyValue.Kind = yaml.ScalarNode
				changed = true
			}
		}
	}
	for _, child := range node.Content {
		childChanged, err := rewriteWireGuardPrivateKeys(child, rewrite)
		if err != nil {
			return false, err
		}
		changed = changed || childChanged
	}
	return changed, nil
}

func normalizeWireGuardYAMLKey(value string) string {
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(value)))
}

func parseWireGuardNodeSecretReference(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, wireGuardNodeSecretReferencePrefix) {
		return 0, false
	}
	nodeID, err := strconv.ParseInt(strings.TrimPrefix(value, wireGuardNodeSecretReferencePrefix), 10, 64)
	return nodeID, err == nil && nodeID > 0
}

func wireGuardPrivateKeyFromNodeConfig(config string) string {
	var proxy map[string]interface{}
	if err := json.Unmarshal([]byte(config), &proxy); err != nil {
		return ""
	}
	for key, value := range proxy {
		if normalizeWireGuardYAMLKey(key) == "privatekey" {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}
