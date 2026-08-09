package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/violetaini/relaydock/internal/secretbox"
)

const wireGuardPrivateKeySecretKind = "wireguard-private-key-v1"

const wireGuardSubscriptionSecretPurpose = "arcway:subscription:wireguard-private-key:v1:"

// ConfigureNodeSecretEncryption derives the at-rest node-secret key from the
// persistent panel master key and atomically protects any legacy plaintext
// WireGuard node configs. Call this once immediately after loading the panel
// master identity and before serving requests.
func (r *TrafficRepository) ConfigureNodeSecretEncryption(masterKey []byte) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	box, err := secretbox.New(masterKey)
	if err != nil {
		return err
	}
	r.nodeSecretMu.Lock()
	r.nodeSecretBox = box
	r.nodeSecretMu.Unlock()
	if err := r.verifyExistingProxyProviderAccessTokens(context.Background()); err != nil {
		r.nodeSecretMu.Lock()
		r.nodeSecretBox = nil
		r.nodeSecretMu.Unlock()
		return err
	}
	if err := r.verifyExistingWireGuardNodeSecrets(context.Background()); err != nil {
		r.nodeSecretMu.Lock()
		r.nodeSecretBox = nil
		r.nodeSecretMu.Unlock()
		return err
	}
	if err := r.verifyExistingWireGuardProbePeerSecrets(context.Background()); err != nil {
		r.nodeSecretMu.Lock()
		r.nodeSecretBox = nil
		r.nodeSecretMu.Unlock()
		return err
	}
	if err := r.ProtectWireGuardNodeSecrets(context.Background()); err != nil {
		r.nodeSecretMu.Lock()
		r.nodeSecretBox = nil
		r.nodeSecretMu.Unlock()
		return err
	}
	if err := r.verifyWireGuardNodeSecrets(context.Background()); err != nil {
		r.nodeSecretMu.Lock()
		r.nodeSecretBox = nil
		r.nodeSecretMu.Unlock()
		return err
	}
	return nil
}

// Existing ciphertext must be checked before migrating any legacy plaintext.
// Otherwise a wrong master key could encrypt legacy rows under the wrong key
// before a previously encrypted row reveals the mismatch.
func (r *TrafficRepository) verifyExistingWireGuardNodeSecrets(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, `
		SELECT ns.node_id, ns.kind, ns.ciphertext
		FROM node_secrets ns
		ORDER BY ns.node_id`)
	if err != nil {
		return fmt.Errorf("scan existing encrypted WireGuard node secrets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID int64
		var kind, ciphertext string
		if err := rows.Scan(&nodeID, &kind, &ciphertext); err != nil {
			return fmt.Errorf("scan existing encrypted WireGuard node secret: %w", err)
		}
		if kind != wireGuardPrivateKeySecretKind || strings.TrimSpace(ciphertext) == "" {
			return fmt.Errorf("WireGuard 节点 %d 的加密私钥记录类型无效", nodeID)
		}
		privateKey, err := r.openWireGuardPrivateKey(nodeID, ciphertext)
		if err != nil {
			return err
		}
		if !validStoredWireGuardPrivateKey(privateKey) {
			return fmt.Errorf("WireGuard 节点 %d 的加密私钥格式无效", nodeID)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate existing encrypted WireGuard node secrets: %w", err)
	}
	return nil
}

func nodeSecretAssociatedData(nodeID int64) []byte {
	return []byte("arcway:node:wireguard-private-key:" + strconv.FormatInt(nodeID, 10))
}

func (r *TrafficRepository) sealWireGuardPrivateKey(nodeID int64, privateKey string) (string, error) {
	r.nodeSecretMu.RLock()
	box := r.nodeSecretBox
	r.nodeSecretMu.RUnlock()
	if box == nil {
		return "", errors.New("WireGuard 私钥加密尚未初始化")
	}
	return box.Seal([]byte(privateKey), nodeSecretAssociatedData(nodeID))
}

func (r *TrafficRepository) openWireGuardPrivateKey(nodeID int64, ciphertext string) (string, error) {
	r.nodeSecretMu.RLock()
	box := r.nodeSecretBox
	r.nodeSecretMu.RUnlock()
	if box == nil {
		return "", errors.New("WireGuard 私钥加密尚未初始化")
	}
	plaintext, err := box.Open(ciphertext, nodeSecretAssociatedData(nodeID))
	if err != nil {
		return "", fmt.Errorf("解密 WireGuard 节点 %d 私钥失败: %w", nodeID, err)
	}
	privateKey := strings.TrimSpace(string(plaintext))
	if privateKey == "" {
		return "", fmt.Errorf("WireGuard 节点 %d 私钥为空", nodeID)
	}
	return privateKey, nil
}

// SealWireGuardSubscriptionPrivateKey encrypts a static subscription snapshot.
// The scope is the subscription filename, so a ciphertext copied to a different
// subscription cannot be decrypted. Static snapshots deliberately do not point
// back to a mutable node: rotating a node key must never grant an old link the
// replacement private key.
func (r *TrafficRepository) SealWireGuardSubscriptionPrivateKey(scope, privateKey string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	scope = strings.TrimSpace(scope)
	privateKey = strings.TrimSpace(privateKey)
	if scope == "" {
		return "", errors.New("subscription secret scope is required")
	}
	if !validStoredWireGuardPrivateKey(privateKey) {
		return "", errors.New("WireGuard private key must contain 32 bytes")
	}
	r.nodeSecretMu.RLock()
	box := r.nodeSecretBox
	r.nodeSecretMu.RUnlock()
	if box == nil {
		return "", errors.New("WireGuard 私钥加密尚未初始化")
	}
	return box.Seal([]byte(privateKey), []byte(wireGuardSubscriptionSecretPurpose+scope))
}

// OpenWireGuardSubscriptionPrivateKey decrypts an authenticated static
// snapshot. Decryption fails when either the envelope or filename scope was
// changed.
func (r *TrafficRepository) OpenWireGuardSubscriptionPrivateKey(scope, ciphertext string) (string, error) {
	if r == nil || r.db == nil {
		return "", errors.New("traffic repository not initialized")
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return "", errors.New("subscription secret scope is required")
	}
	r.nodeSecretMu.RLock()
	box := r.nodeSecretBox
	r.nodeSecretMu.RUnlock()
	if box == nil {
		return "", errors.New("WireGuard 私钥加密尚未初始化")
	}
	plaintext, err := box.Open(strings.TrimSpace(ciphertext), []byte(wireGuardSubscriptionSecretPurpose+scope))
	if err != nil {
		return "", fmt.Errorf("解密 WireGuard 订阅私钥失败: %w", err)
	}
	privateKey := strings.TrimSpace(string(plaintext))
	if !validStoredWireGuardPrivateKey(privateKey) {
		return "", errors.New("WireGuard 订阅私钥格式无效")
	}
	return privateKey, nil
}

func validStoredWireGuardPrivateKey(value string) bool {
	_, err := decodeStoredWireGuardPrivateKey(value)
	return err == nil
}

func decodeStoredWireGuardPrivateKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if len(value) == 64 {
		decoded, err := hex.DecodeString(value)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, errors.New("WireGuard private key must contain 32 bytes")
}

func equalStoredWireGuardPrivateKeys(first, second string) bool {
	firstBytes, firstErr := decodeStoredWireGuardPrivateKey(first)
	secondBytes, secondErr := decodeStoredWireGuardPrivateKey(second)
	return firstErr == nil && secondErr == nil && bytes.Equal(firstBytes, secondBytes)
}

func (r *TrafficRepository) verifyWireGuardNodeSecrets(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, `
		SELECT n.id, n.username, n.raw_url, n.node_name, n.protocol,
		       n.parsed_config, n.clash_config,
		       COALESCE(ns.kind, ''), COALESCE(ns.ciphertext, '')
		FROM nodes n
		LEFT JOIN node_secrets ns ON ns.node_id = n.id
		ORDER BY n.id`)
	if err != nil {
		return fmt.Errorf("scan encrypted WireGuard node secrets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var node Node
		var kind, ciphertext string
		if err := rows.Scan(
			&node.ID, &node.Username, &node.RawURL, &node.NodeName, &node.Protocol,
			&node.ParsedConfig, &node.ClashConfig, &kind, &ciphertext,
		); err != nil {
			return fmt.Errorf("scan encrypted WireGuard node secret: %w", err)
		}
		isWireGuard, err := validateNodeProtocolEvidence(&node)
		if err != nil {
			return fmt.Errorf("validate node %d protocol: %w", node.ID, err)
		}
		if !isWireGuard {
			if kind != "" || ciphertext != "" {
				return fmt.Errorf("non-WireGuard node %d contains an encrypted WireGuard secret", node.ID)
			}
			continue
		}
		if node.Protocol != "wireguard" {
			return fmt.Errorf("WireGuard node %d protocol is not canonical", node.ID)
		}
		if plaintext, err := findWireGuardPlaintextPrivateKey(node); err != nil {
			return fmt.Errorf("inspect WireGuard node %d private key: %w", node.ID, err)
		} else if plaintext != "" {
			return fmt.Errorf("WireGuard node %d still contains an unprotected private key", node.ID)
		}
		if kind != wireGuardPrivateKeySecretKind || strings.TrimSpace(ciphertext) == "" {
			return fmt.Errorf("WireGuard 节点 %d 缺少有效的加密私钥记录", node.ID)
		}
		privateKey, err := r.openWireGuardPrivateKey(node.ID, ciphertext)
		if err != nil {
			return err
		}
		if !validStoredWireGuardPrivateKey(privateKey) {
			return fmt.Errorf("WireGuard 节点 %d 的加密私钥格式无效", node.ID)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate encrypted WireGuard node secrets: %w", err)
	}
	return nil
}

func (r *TrafficRepository) nodeSecretKind(ctx context.Context, nodeID int64) (string, bool, error) {
	var kind string
	err := r.db.QueryRowContext(ctx, `SELECT kind FROM node_secrets WHERE node_id = ? LIMIT 1`, nodeID).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read node %d secret state: %w", nodeID, err)
	}
	return kind, true, nil
}

func normalizePrivateKeyField(key string) string {
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(key)))
}

func canonicalNodeProtocol(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "wg" {
		return "wireguard"
	}
	return protocol
}

type nodeConfigProtocolEvidence struct {
	wireGuard            bool
	explicitNonWireGuard string
}

func containsPrivateKeyField(value interface{}) bool {
	switch current := value.(type) {
	case map[string]interface{}:
		for key, child := range current {
			if normalizePrivateKeyField(key) == "privatekey" || containsPrivateKeyField(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range current {
			if containsPrivateKeyField(child) {
				return true
			}
		}
	}
	return false
}

func inspectNodeConfigProtocol(label, config string) (nodeConfigProtocolEvidence, error) {
	config = strings.TrimSpace(config)
	if config == "" {
		return nodeConfigProtocolEvidence{}, nil
	}
	var value interface{}
	if err := json.Unmarshal([]byte(config), &value); err != nil {
		// Ordinary legacy nodes were not required to keep parsed_config as JSON.
		// Preserve that compatibility, but fail closed when malformed input still
		// advertises a private-key field that could contain a WireGuard identity.
		normalized := normalizePrivateKeyField(config)
		if strings.Contains(normalized, "privatekey") {
			return nodeConfigProtocolEvidence{}, fmt.Errorf("%s contains an unreadable private-key field", label)
		}
		return nodeConfigProtocolEvidence{}, nil
	}
	evidence := nodeConfigProtocolEvidence{wireGuard: containsPrivateKeyField(value)}
	mapping, ok := value.(map[string]interface{})
	if !ok || mapping == nil {
		return evidence, nil
	}
	var explicit string
	for key, raw := range mapping {
		normalizedKey := normalizePrivateKeyField(key)
		if normalizedKey != "type" && normalizedKey != "protocol" {
			continue
		}
		protocol, ok := raw.(string)
		if !ok {
			return nodeConfigProtocolEvidence{}, fmt.Errorf("%s %s must be a string", label, key)
		}
		protocol = canonicalNodeProtocol(protocol)
		if protocol == "" {
			continue
		}
		if explicit != "" && explicit != protocol {
			return nodeConfigProtocolEvidence{}, fmt.Errorf("%s contains conflicting type/protocol values", label)
		}
		explicit = protocol
	}
	if explicit == "wireguard" {
		evidence.wireGuard = true
	} else if explicit != "" {
		evidence.explicitNonWireGuard = explicit
	}
	if evidence.wireGuard && evidence.explicitNonWireGuard != "" {
		return nodeConfigProtocolEvidence{}, fmt.Errorf("%s declares %s but contains WireGuard private material", label, evidence.explicitNonWireGuard)
	}
	return evidence, nil
}

// validateNodeProtocolEvidence makes the database protocol an assertion rather
// than a trust boundary. WireGuard evidence in any persisted representation
// must agree with the declared protocol, and the historical wg alias is
// canonicalized before storage.
func validateNodeProtocolEvidence(node *Node) (bool, error) {
	if node == nil {
		return false, errors.New("node is required")
	}
	node.Protocol = canonicalNodeProtocol(node.Protocol)
	declaredWireGuard := node.Protocol == "wireguard"
	actualWireGuard := false
	for _, candidate := range []struct {
		label  string
		config string
	}{
		{label: "parsed_config", config: node.ParsedConfig},
		{label: "clash_config", config: node.ClashConfig},
	} {
		evidence, err := inspectNodeConfigProtocol(candidate.label, candidate.config)
		if err != nil {
			return false, err
		}
		if evidence.wireGuard {
			actualWireGuard = true
		}
		if declaredWireGuard && evidence.explicitNonWireGuard != "" {
			return false, fmt.Errorf("protocol wireguard conflicts with %s type %s", candidate.label, evidence.explicitNonWireGuard)
		}
	}
	if _, isWireGuardURL, err := privateKeyFromWireGuardURL(node.RawURL); err != nil {
		return false, err
	} else if isWireGuardURL {
		actualWireGuard = true
	}
	if actualWireGuard && !declaredWireGuard {
		return false, fmt.Errorf("protocol %q conflicts with WireGuard config", node.Protocol)
	}
	return declaredWireGuard, nil
}

func stripPrivateKeyFields(value interface{}, found *string) error {
	switch current := value.(type) {
	case map[string]interface{}:
		for key, child := range current {
			if normalizePrivateKeyField(key) == "privatekey" {
				privateKey, ok := child.(string)
				if !ok || strings.TrimSpace(privateKey) == "" {
					return fmt.Errorf("WireGuard %s must be a non-empty string", key)
				}
				privateKey = strings.TrimSpace(privateKey)
				if *found != "" && *found != privateKey {
					return errors.New("WireGuard configs contain conflicting private keys")
				}
				*found = privateKey
				delete(current, key)
				continue
			}
			if err := stripPrivateKeyFields(child, found); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range current {
			if err := stripPrivateKeyFields(child, found); err != nil {
				return err
			}
		}
	}
	return nil
}

func stripWireGuardPrivateKeyJSON(config string, found *string) (string, error) {
	config = strings.TrimSpace(config)
	if config == "" {
		return "", nil
	}
	var value map[string]interface{}
	if err := json.Unmarshal([]byte(config), &value); err != nil {
		return "", errors.New("WireGuard config must be a JSON object")
	}
	if value == nil {
		return "", errors.New("WireGuard config must be a JSON object")
	}
	if err := stripPrivateKeyFields(value, found); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode protected WireGuard config: %w", err)
	}
	return string(encoded), nil
}

func privateKeyFromWireGuardURL(rawURL string) (string, bool, error) {
	rawURL = strings.TrimSpace(rawURL)
	lower := strings.ToLower(rawURL)
	if !strings.HasPrefix(lower, "wireguard://") && !strings.HasPrefix(lower, "wg://") {
		return "", false, nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", true, fmt.Errorf("parse WireGuard raw URL: %w", err)
	}
	if parsed.User == nil || strings.TrimSpace(parsed.User.Username()) == "" {
		return "", true, errors.New("WireGuard raw URL does not contain a private key")
	}
	privateKey, err := url.PathUnescape(parsed.User.Username())
	if err != nil {
		return "", true, fmt.Errorf("decode WireGuard raw URL private key: %w", err)
	}
	return strings.TrimSpace(privateKey), true, nil
}

// protectWireGuardNodeForStorage removes private material from fields stored in
// nodes. The returned key must be sealed into node_secrets in the same DB
// transaction as the node write.
func protectWireGuardNodeForStorage(node Node) (Node, string, error) {
	isWireGuard, err := validateNodeProtocolEvidence(&node)
	if err != nil {
		return Node{}, "", err
	}
	if !isWireGuard {
		return node, "", nil
	}
	privateKey := ""
	node.ParsedConfig, err = stripWireGuardPrivateKeyJSON(node.ParsedConfig, &privateKey)
	if err != nil {
		return Node{}, "", err
	}
	node.ClashConfig, err = stripWireGuardPrivateKeyJSON(node.ClashConfig, &privateKey)
	if err != nil {
		return Node{}, "", err
	}
	if rawKey, isWireGuardURL, err := privateKeyFromWireGuardURL(node.RawURL); err != nil {
		return Node{}, "", err
	} else if isWireGuardURL {
		if privateKey != "" && !equalStoredWireGuardPrivateKeys(rawKey, privateKey) {
			return Node{}, "", errors.New("WireGuard raw URL and configs contain conflicting private keys")
		}
		privateKey = rawKey
	}
	// WireGuard URIs carry client identity in userinfo. Even an unrecognized URL
	// must not be retained as a second plaintext secret source.
	node.RawURL = ""
	if privateKey != "" && !validStoredWireGuardPrivateKey(privateKey) {
		return Node{}, "", errors.New("WireGuard private key must contain 32 bytes")
	}
	return node, privateKey, nil
}

func injectWireGuardPrivateKeyJSON(config, privateKey string) (string, error) {
	config = strings.TrimSpace(config)
	if config == "" {
		return "", nil
	}
	var value map[string]interface{}
	if err := json.Unmarshal([]byte(config), &value); err != nil {
		return "", fmt.Errorf("decode protected WireGuard config: %w", err)
	}
	value["private-key"] = privateKey
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("hydrate protected WireGuard config: %w", err)
	}
	return string(encoded), nil
}

func findWireGuardPlaintextPrivateKey(node Node) (string, error) {
	isWireGuard, err := validateNodeProtocolEvidence(&node)
	if err != nil {
		return "", err
	}
	if !isWireGuard {
		return "", nil
	}
	privateKey := ""
	if _, err := stripWireGuardPrivateKeyJSON(node.ParsedConfig, &privateKey); err != nil {
		return "", err
	}
	if _, err := stripWireGuardPrivateKeyJSON(node.ClashConfig, &privateKey); err != nil {
		return "", err
	}
	if rawKey, isWireGuardURL, err := privateKeyFromWireGuardURL(node.RawURL); err != nil {
		return "", err
	} else if isWireGuardURL {
		if privateKey != "" && privateKey != rawKey {
			return "", errors.New("WireGuard raw URL and configs contain conflicting private keys")
		}
		privateKey = rawKey
	}
	return privateKey, nil
}

func (r *TrafficRepository) hydrateWireGuardNodeSecret(ctx context.Context, node *Node) error {
	if node == nil {
		return nil
	}
	isWireGuard, err := validateNodeProtocolEvidence(node)
	if err != nil {
		return fmt.Errorf("validate node %d protocol: %w", node.ID, err)
	}
	if !isWireGuard {
		return nil
	}
	if plaintext, err := findWireGuardPlaintextPrivateKey(*node); err != nil {
		return fmt.Errorf("inspect WireGuard node %d private key: %w", node.ID, err)
	} else if plaintext != "" {
		return fmt.Errorf("WireGuard node %d still contains an unprotected private key", node.ID)
	}
	var ciphertext string
	err = r.db.QueryRowContext(ctx,
		`SELECT ciphertext FROM node_secrets WHERE node_id = ? AND kind = ? LIMIT 1`,
		node.ID, wireGuardPrivateKeySecretKind,
	).Scan(&ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("WireGuard 节点 %d 缺少加密私钥", node.ID)
	}
	if err != nil {
		return fmt.Errorf("read WireGuard node %d secret: %w", node.ID, err)
	}
	privateKey, err := r.openWireGuardPrivateKey(node.ID, ciphertext)
	if err != nil {
		return err
	}
	node.ParsedConfig, err = injectWireGuardPrivateKeyJSON(node.ParsedConfig, privateKey)
	if err != nil {
		return err
	}
	node.ClashConfig, err = injectWireGuardPrivateKeyJSON(node.ClashConfig, privateKey)
	return err
}

func (r *TrafficRepository) hydrateWireGuardNodeSecrets(ctx context.Context, nodes []Node) error {
	for index := range nodes {
		if err := r.hydrateWireGuardNodeSecret(ctx, &nodes[index]); err != nil {
			return err
		}
	}
	return nil
}

func upsertNodeSecret(ctx context.Context, tx *sql.Tx, nodeID int64, ciphertext string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO node_secrets(node_id, kind, ciphertext)
		VALUES(?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET
			kind = excluded.kind,
			ciphertext = excluded.ciphertext,
			updated_at = CURRENT_TIMESTAMP`,
		nodeID, wireGuardPrivateKeySecretKind, ciphertext,
	)
	return err
}

// ProtectWireGuardNodeSecrets is an idempotent migration for nodes imported by
// earlier panel versions, where client private keys lived in plaintext JSON or
// wireguard:// URLs. All validation and encryption happens before the write
// transaction so a failure cannot partially strip usable data.
func (r *TrafficRepository) ProtectWireGuardNodeSecrets(ctx context.Context) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT n.id, n.username, n.raw_url, n.node_name, n.protocol, n.parsed_config, n.clash_config,
		       COALESCE(ns.kind, ''), COALESCE(ns.ciphertext, '')
		FROM nodes n
		LEFT JOIN node_secrets ns ON ns.node_id = n.id
		ORDER BY n.id`)
	if err != nil {
		return fmt.Errorf("scan legacy WireGuard secrets: %w", err)
	}
	type migration struct {
		node            Node
		ciphertext      string
		updateNode      bool
		writeCiphertext bool
	}
	var migrations []migration
	for rows.Next() {
		var node Node
		var existingKind, existingCiphertext string
		if err := rows.Scan(
			&node.ID, &node.Username, &node.RawURL, &node.NodeName, &node.Protocol,
			&node.ParsedConfig, &node.ClashConfig, &existingKind, &existingCiphertext,
		); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan legacy WireGuard node: %w", err)
		}
		protected, privateKey, err := protectWireGuardNodeForStorage(node)
		if err != nil {
			_ = rows.Close()
			return fmt.Errorf("protect legacy WireGuard node %d: %w", node.ID, err)
		}
		isWireGuard := protected.Protocol == "wireguard"
		if !isWireGuard {
			if existingKind != "" || existingCiphertext != "" {
				_ = rows.Close()
				return fmt.Errorf("non-WireGuard node %d contains an encrypted WireGuard secret", node.ID)
			}
			continue
		}
		if existingKind != "" && existingKind != wireGuardPrivateKeySecretKind {
			_ = rows.Close()
			return fmt.Errorf("WireGuard node %d contains an unsupported encrypted secret", node.ID)
		}
		updateNode := protected.Protocol != strings.ToLower(strings.TrimSpace(node.Protocol)) ||
			protected.RawURL != node.RawURL || protected.ParsedConfig != node.ParsedConfig || protected.ClashConfig != node.ClashConfig
		if privateKey == "" {
			if existingCiphertext == "" {
				_ = rows.Close()
				return fmt.Errorf("WireGuard 节点 %d 缺少有效的加密私钥记录", node.ID)
			}
			if updateNode {
				migrations = append(migrations, migration{node: protected, ciphertext: existingCiphertext, updateNode: true})
			}
			continue
		}
		if existingCiphertext != "" {
			existingPrivateKey, err := r.openWireGuardPrivateKey(node.ID, existingCiphertext)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("read existing WireGuard node %d secret during migration: %w", node.ID, err)
			}
			if !equalStoredWireGuardPrivateKeys(existingPrivateKey, privateKey) {
				_ = rows.Close()
				return fmt.Errorf("WireGuard node %d plaintext private key conflicts with its encrypted identity", node.ID)
			}
			migrations = append(migrations, migration{node: protected, ciphertext: existingCiphertext, updateNode: updateNode})
			continue
		}
		ciphertext, err := r.sealWireGuardPrivateKey(node.ID, privateKey)
		if err != nil {
			_ = rows.Close()
			return fmt.Errorf("encrypt legacy WireGuard node %d: %w", node.ID, err)
		}
		migrations = append(migrations, migration{node: protected, ciphertext: ciphertext, updateNode: updateNode, writeCiphertext: true})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate legacy WireGuard nodes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy WireGuard scan: %w", err)
	}
	if len(migrations) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin WireGuard secret migration: %w", err)
	}
	defer tx.Rollback()
	for _, item := range migrations {
		if item.updateNode {
			if _, err := tx.ExecContext(ctx, `
				UPDATE nodes SET protocol = ?, raw_url = ?, parsed_config = ?, clash_config = ?, updated_at = CURRENT_TIMESTAMP
				WHERE id = ?`,
				item.node.Protocol, item.node.RawURL, item.node.ParsedConfig, item.node.ClashConfig, item.node.ID,
			); err != nil {
				return fmt.Errorf("strip legacy WireGuard node %d secret: %w", item.node.ID, err)
			}
		}
		if item.writeCiphertext {
			if err := upsertNodeSecret(ctx, tx, item.node.ID, item.ciphertext); err != nil {
				return fmt.Errorf("store legacy WireGuard node %d secret: %w", item.node.ID, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit WireGuard secret migration: %w", err)
	}
	// Rebuild the database after removing legacy plaintext so old row payloads
	// do not remain recoverable from free pages or the WAL.
	if _, err := r.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint WireGuard secret migration: %w", err)
	}
	if _, err := r.db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("compact WireGuard secret migration: %w", err)
	}
	if _, err := r.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("finalize WireGuard secret migration: %w", err)
	}
	return nil
}
