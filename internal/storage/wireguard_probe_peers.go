package storage

import (
	"context"
	"crypto/ecdh"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const wireGuardProbePeerSecretPurpose = "arcway:probe:wireguard-peer:v1:"

const (
	WireGuardProbePeerStatePending = "pending"
	WireGuardProbePeerStateActive  = "active"
)

var ErrWireGuardProbePeerNotFound = errors.New("WireGuard probe peer not found")

// WireGuardProbePeer is a dedicated client identity used only for active
// WireGuard probes. PrivateKey is decrypted on read and is never serialized.
type WireGuardProbePeer struct {
	ResourceID int64     `json:"resource_id"`
	PublicKey  string    `json:"public_key"`
	PrivateKey string    `json:"-"`
	Addresses  []string  `json:"addresses"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (r *TrafficRepository) migrateWireGuardProbePeers() error {
	const schema = `
CREATE TABLE IF NOT EXISTS wireguard_probe_peers (
    resource_id INTEGER PRIMARY KEY,
    public_key TEXT NOT NULL UNIQUE,
    private_key_ciphertext TEXT NOT NULL,
    addresses_json TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'active')),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(resource_id) REFERENCES managed_inbound_resources(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_wireguard_probe_peers_state
    ON wireguard_probe_peers(state);
CREATE TRIGGER IF NOT EXISTS trg_managed_inbound_resource_delete_wireguard_probe_peer
AFTER DELETE ON managed_inbound_resources
BEGIN
    DELETE FROM wireguard_probe_peers WHERE resource_id = OLD.id;
END;
`
	if _, err := r.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate wireguard_probe_peers: %w", err)
	}
	return nil
}

func wireGuardProbePeerAssociatedData(resourceID int64) []byte {
	return []byte(wireGuardProbePeerSecretPurpose + strconv.FormatInt(resourceID, 10))
}

func canonicalWireGuardProbeKey(value string) (string, []byte, error) {
	decoded, err := decodeStoredWireGuardPrivateKey(value)
	if err != nil {
		return "", nil, err
	}
	return base64.StdEncoding.EncodeToString(decoded), decoded, nil
}

func normalizeWireGuardProbeAddresses(addresses []string) ([]string, error) {
	if len(addresses) == 0 {
		return nil, errors.New("at least one WireGuard probe address is required")
	}
	if len(addresses) > 8 {
		return nil, errors.New("WireGuard probe addresses cannot exceed 8 entries")
	}
	normalized := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid WireGuard probe address %q: %w", value, err)
		}
		addr := prefix.Addr()
		if addr.IsUnspecified() || addr.IsMulticast() {
			return nil, fmt.Errorf("invalid WireGuard probe address %q", value)
		}
		canonical := prefix.String()
		if _, exists := seen[canonical]; exists {
			return nil, fmt.Errorf("duplicate WireGuard probe address %q", canonical)
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}

func normalizeWireGuardProbePeer(peer *WireGuardProbePeer) error {
	if peer == nil {
		return errors.New("WireGuard probe peer is required")
	}
	if peer.ResourceID <= 0 {
		return errors.New("managed inbound resource id is required")
	}
	publicKey, privateKey, err := normalizeWireGuardProbeKeyPair(peer.PublicKey, peer.PrivateKey)
	if err != nil {
		return err
	}
	addresses, err := normalizeWireGuardProbeAddresses(peer.Addresses)
	if err != nil {
		return err
	}
	state := strings.ToLower(strings.TrimSpace(peer.State))
	if state == "" {
		state = WireGuardProbePeerStatePending
	}
	if state != WireGuardProbePeerStatePending {
		return errors.New("new WireGuard probe peer state must be pending")
	}
	peer.PublicKey = publicKey
	peer.PrivateKey = privateKey
	peer.Addresses = addresses
	peer.State = state
	return nil
}

func normalizeWireGuardProbeKeyPair(publicValue, privateValue string) (string, string, error) {
	publicKey, publicBytes, err := canonicalWireGuardProbeKey(publicValue)
	if err != nil {
		return "", "", fmt.Errorf("WireGuard probe public key must contain 32 bytes: %w", err)
	}
	privateKey, privateBytes, err := canonicalWireGuardProbeKey(privateValue)
	if err != nil {
		return "", "", fmt.Errorf("WireGuard probe private key must contain 32 bytes: %w", err)
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return "", "", fmt.Errorf("parse WireGuard probe private key: %w", err)
	}
	derived := private.PublicKey().Bytes()
	if len(derived) != len(publicBytes) || subtle.ConstantTimeCompare(derived, publicBytes) != 1 {
		return "", "", errors.New("WireGuard probe public key does not match private key")
	}
	return publicKey, privateKey, nil
}

func (r *TrafficRepository) sealWireGuardProbePrivateKey(resourceID int64, privateKey string) (string, error) {
	r.nodeSecretMu.RLock()
	box := r.nodeSecretBox
	r.nodeSecretMu.RUnlock()
	if box == nil {
		return "", errors.New("WireGuard probe private-key encryption is not initialized")
	}
	return box.Seal([]byte(privateKey), wireGuardProbePeerAssociatedData(resourceID))
}

func (r *TrafficRepository) openWireGuardProbePrivateKey(resourceID int64, ciphertext string) (string, error) {
	r.nodeSecretMu.RLock()
	box := r.nodeSecretBox
	r.nodeSecretMu.RUnlock()
	if box == nil {
		return "", errors.New("WireGuard probe private-key encryption is not initialized")
	}
	plaintext, err := box.Open(strings.TrimSpace(ciphertext), wireGuardProbePeerAssociatedData(resourceID))
	if err != nil {
		return "", fmt.Errorf("decrypt WireGuard probe private key for resource %d: %w", resourceID, err)
	}
	privateKey, _, err := canonicalWireGuardProbeKey(string(plaintext))
	if err != nil {
		return "", fmt.Errorf("WireGuard probe private key for resource %d is invalid: %w", resourceID, err)
	}
	return privateKey, nil
}

func (r *TrafficRepository) verifyExistingWireGuardProbePeerSecrets(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, `
SELECT resource_id, public_key, private_key_ciphertext
FROM wireguard_probe_peers
ORDER BY resource_id`)
	if err != nil {
		return fmt.Errorf("scan encrypted WireGuard probe peer secrets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var resourceID int64
		var publicKey, ciphertext string
		if err := rows.Scan(&resourceID, &publicKey, &ciphertext); err != nil {
			return fmt.Errorf("scan encrypted WireGuard probe peer secret: %w", err)
		}
		privateKey, err := r.openWireGuardProbePrivateKey(resourceID, ciphertext)
		if err != nil {
			return err
		}
		if _, _, err := normalizeWireGuardProbeKeyPair(publicKey, privateKey); err != nil {
			return fmt.Errorf("validate WireGuard probe peer secret for resource %d: %w", resourceID, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate encrypted WireGuard probe peer secrets: %w", err)
	}
	return nil
}

type wireGuardProbePeerScanner interface {
	Scan(dest ...interface{}) error
}

func (r *TrafficRepository) scanWireGuardProbePeer(scanner wireGuardProbePeerScanner) (*WireGuardProbePeer, error) {
	var peer WireGuardProbePeer
	var ciphertext, addressesJSON string
	if err := scanner.Scan(
		&peer.ResourceID,
		&peer.PublicKey,
		&ciphertext,
		&addressesJSON,
		&peer.State,
		&peer.CreatedAt,
		&peer.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrWireGuardProbePeerNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(addressesJSON), &peer.Addresses); err != nil {
		return nil, fmt.Errorf("decode WireGuard probe peer addresses for resource %d: %w", peer.ResourceID, err)
	}
	addresses, err := normalizeWireGuardProbeAddresses(peer.Addresses)
	if err != nil {
		return nil, fmt.Errorf("validate WireGuard probe peer addresses for resource %d: %w", peer.ResourceID, err)
	}
	peer.Addresses = addresses
	privateKey, err := r.openWireGuardProbePrivateKey(peer.ResourceID, ciphertext)
	if err != nil {
		return nil, err
	}
	publicKey, privateKey, err := normalizeWireGuardProbeKeyPair(peer.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("validate WireGuard probe peer key pair for resource %d: %w", peer.ResourceID, err)
	}
	peer.PublicKey = publicKey
	peer.PrivateKey = privateKey
	return &peer, nil
}

const wireGuardProbePeerSelect = `
SELECT resource_id, public_key, private_key_ciphertext, addresses_json,
       state, created_at, updated_at
FROM wireguard_probe_peers`

// CreateWireGuardProbePeer stores a pending peer for a managed WireGuard
// inbound. The private key is encrypted before it reaches SQLite.
func (r *TrafficRepository) CreateWireGuardProbePeer(ctx context.Context, peer WireGuardProbePeer) (*WireGuardProbePeer, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if err := normalizeWireGuardProbePeer(&peer); err != nil {
		return nil, err
	}
	ciphertext, err := r.sealWireGuardProbePrivateKey(peer.ResourceID, peer.PrivateKey)
	if err != nil {
		return nil, err
	}
	addressesJSON, err := json.Marshal(peer.Addresses)
	if err != nil {
		return nil, fmt.Errorf("encode WireGuard probe peer addresses: %w", err)
	}
	now := time.Now().UTC()
	result, err := r.db.ExecContext(ctx, `
INSERT INTO wireguard_probe_peers
    (resource_id, public_key, private_key_ciphertext, addresses_json, state, created_at, updated_at)
SELECT id, ?, ?, ?, ?, ?, ?
FROM managed_inbound_resources
WHERE id = ? AND LOWER(TRIM(protocol)) = 'wireguard'`,
		peer.PublicKey, ciphertext, string(addressesJSON), peer.State, now, now, peer.ResourceID,
	)
	if err != nil {
		return nil, fmt.Errorf("create WireGuard probe peer: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("read created WireGuard probe peer count: %w", err)
	}
	if count == 0 {
		return nil, errors.New("managed WireGuard inbound resource not found")
	}
	return r.GetWireGuardProbePeer(ctx, peer.ResourceID)
}

func (r *TrafficRepository) GetWireGuardProbePeer(ctx context.Context, resourceID int64) (*WireGuardProbePeer, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if resourceID <= 0 {
		return nil, ErrWireGuardProbePeerNotFound
	}
	return r.scanWireGuardProbePeer(r.db.QueryRowContext(ctx, wireGuardProbePeerSelect+` WHERE resource_id = ?`, resourceID))
}

func (r *TrafficRepository) MarkWireGuardProbePeerActive(ctx context.Context, resourceID int64) (*WireGuardProbePeer, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("traffic repository not initialized")
	}
	if resourceID <= 0 {
		return nil, ErrWireGuardProbePeerNotFound
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE wireguard_probe_peers
SET state = 'active', updated_at = ?
WHERE resource_id = ?`, time.Now().UTC(), resourceID)
	if err != nil {
		return nil, fmt.Errorf("mark WireGuard probe peer active: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("read activated WireGuard probe peer count: %w", err)
	}
	if count == 0 {
		return nil, ErrWireGuardProbePeerNotFound
	}
	return r.GetWireGuardProbePeer(ctx, resourceID)
}

// MarkWireGuardProbePeerPending forces the next probe to reconcile the Agent
// before reusing a previously active identity. A missing peer is a no-op.
func (r *TrafficRepository) MarkWireGuardProbePeerPending(ctx context.Context, resourceID int64) error {
	if r == nil || r.db == nil {
		return errors.New("traffic repository not initialized")
	}
	if resourceID <= 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
UPDATE wireguard_probe_peers
SET state = 'pending', updated_at = ?
WHERE resource_id = ? AND state = 'active'`, time.Now().UTC(), resourceID)
	if err != nil {
		return fmt.Errorf("mark WireGuard probe peer pending: %w", err)
	}
	return nil
}
